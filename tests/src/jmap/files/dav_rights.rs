/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{
    account::Account,
    jmap::JmapUtils,
    server::TestServer,
    webdav::{DavResponse, DummyWebDavClient},
};
use ahash::AHashSet;
use hyper::{Method, StatusCode, header::AUTHORIZATION};
use jmap_proto::request::method::MethodObject;
use serde_json::{Value, json};
use std::time::Duration;

const JOHN_BASE: &str = "/dav/file/jdoe%40example.com";
const JANE_BASE: &str = "/dav/file/jane.smith%40example.com";
const JANE_PRINCIPAL: &str = "/dav/pal/jane.smith%40example.com/";

pub async fn test(test: &TestServer) {
    println!("Running File Storage WebDAV rights tests...");
    let john = test.account("jdoe@example.com");
    let jane = test.account("jane.smith@example.com");
    let bill = test.account("bill@example.com");
    let jane_id = jane.id_string().to_string();
    let bill_id = bill.id_string().to_string();
    let john_client = john.webdav_client();
    let jane_client = jane.webdav_client();
    let bill_client = bill.webdav_client();
    let blob_id = upload_blob(john, "dav rights").await;

    let response = john
        .jmap_create(
            MethodObject::FileNode,
            [
                json!({"name": "dav rights"}),
                json!({"name": "shared", "parentId": "#i0"}),
                json!({"name": "sub", "parentId": "#i1"}),
                json!({"name": "doc.txt", "parentId": "#i1", "blobId": &blob_id}),
                json!({"name": "keep", "parentId": "#i1"}),
                json!({"name": "inner.txt", "parentId": "#i4", "blobId": &blob_id}),
                json!({"name": "proj", "parentId": "#i0"}),
                json!({"name": "x.txt", "parentId": "#i6", "blobId": &blob_id}),
                json!({"name": "moving", "parentId": "#i0"}),
                json!({"name": "a.txt", "parentId": "#i8", "blobId": &blob_id}),
                json!({"name": "deeper", "parentId": "#i8"}),
                json!({"name": "b.txt", "parentId": "#i10", "blobId": &blob_id}),
                json!({"name": "target", "parentId": "#i0"}),
                json!({"name": "f.txt", "parentId": "#i0", "blobId": &blob_id}),
                json!({"name": "link", "parentId": "#i0", "target": ["f.txt"]}),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let ids = (0..15)
        .map(|idx| response.created(idx).id().to_string())
        .collect::<Vec<_>>();
    let [
        root_id,
        shared_id,
        _,
        doc_id,
        _,
        inner_id,
        proj_id,
        _,
        moving_id,
        moving_file_id,
        deeper_id,
        deeper_file_id,
        target_id,
        _,
        _,
    ] = ids.as_slice()
    else {
        panic!("unexpected number of created nodes");
    };
    let root = format!("{JOHN_BASE}/dav%20rights");
    let shared = format!("{root}/shared");

    raw_request(
        &john_client,
        "MOVE",
        &format!("{root}/f.txt"),
        &[
            ("destination", format!("{root}/free.txt")),
            ("destination", format!("{root}/proj/x.txt")),
        ],
    )
    .await
    .with_status(StatusCode::BAD_REQUEST);

    for destination in [
        format!("{root}/.."),
        format!("{root}/%2E%2E"),
        format!("{root}/."),
        format!("{root}/x%01y"),
    ] {
        john_client
            .request_with_headers(
                "MOVE",
                &format!("{root}/f.txt"),
                [("destination", destination.as_str())],
                "",
            )
            .await
            .with_status(StatusCode::BAD_REQUEST);
    }
    john_client
        .request_with_headers(
            "PUT",
            &format!("{root}/x%01y.txt"),
            [("content-type", "text/plain")],
            "hello",
        )
        .await
        .with_status(StatusCode::BAD_REQUEST);
    john_client
        .request("MKCOL", &format!("{root}/x%7Fy"), "")
        .await
        .with_status(StatusCode::BAD_REQUEST);
    john_client
        .request_with_headers(
            "PUT",
            &format!("{root}/a%2Fb/c.txt"),
            [("content-type", "text/plain")],
            "hello",
        )
        .await
        .with_status(StatusCode::BAD_REQUEST);
    john_client
        .request("GET", &format!("{root}/a%00b/c.txt"), "")
        .await
        .with_status(StatusCode::BAD_REQUEST);

    for parent in ["f.txt", "link"] {
        john_client
            .request("MKCOL", &format!("{root}/{parent}/sub"), "")
            .await
            .with_status(StatusCode::CONFLICT);
        john_client
            .request_with_headers(
                "PUT",
                &format!("{root}/{parent}/new.txt"),
                [("content-type", "text/plain")],
                "hello",
            )
            .await
            .with_status(StatusCode::CONFLICT);
        for method in ["MOVE", "COPY"] {
            john_client
                .request_with_headers(
                    method,
                    &format!("{root}/proj/x.txt"),
                    [("destination", format!("{root}/{parent}/x.txt").as_str())],
                    "",
                )
                .await
                .with_status(StatusCode::CONFLICT);
        }
    }
    john_client
        .request("MKCOL", &format!("{root}/link"), "")
        .await
        .with_status(StatusCode::CONFLICT);
    john_client
        .acl(&format!("{root}/link"), JANE_PRINCIPAL, ["read"])
        .await
        .with_status(StatusCode::NOT_FOUND);
    john_client
        .lock_create(&format!("{root}/link"), "owner", true, "0", "Second-300")
        .await
        .with_status(StatusCode::NOT_FOUND);

    let spelled = format!("{root}/file%281%29.txt");
    john_client
        .request_with_headers("PUT", &spelled, [("content-type", "text/plain")], "one")
        .await
        .with_status(StatusCode::CREATED);
    let lock_token = john_client
        .lock_create(&spelled, "owner", true, "0", "Second-300")
        .await
        .with_status(StatusCode::CREATED)
        .lock_token()
        .to_string();
    john_client
        .request_with_headers("PUT", &spelled, [("content-type", "text/plain")], "two")
        .await
        .with_status(StatusCode::LOCKED);
    let condition = format!("<{spelled}> (<{lock_token}>)");
    john_client
        .request_with_headers(
            "PUT",
            &spelled,
            [("content-type", "text/plain"), ("if", condition.as_str())],
            "two",
        )
        .await
        .with_status(StatusCode::NO_CONTENT);
    john_client
        .unlock(&spelled, &lock_token)
        .await
        .with_status(StatusCode::NO_CONTENT);

    let locks = format!("{root}/locks");
    john_client
        .request("MKCOL", &locks, "")
        .await
        .with_status(StatusCode::CREATED);
    let mut tokens = Vec::new();
    for name in ["one.txt", "two.txt"] {
        let path = format!("{locks}/{name}");
        john_client
            .request_with_headers("PUT", &path, [("content-type", "text/plain")], "x")
            .await
            .with_status(StatusCode::CREATED);
        tokens.push((
            path.clone(),
            john_client
                .lock_create(&path, "owner", true, "0", "Second-300")
                .await
                .with_status(StatusCode::CREATED)
                .lock_token()
                .to_string(),
        ));
    }
    let one_token = format!("<{}> (<{}>)", tokens[0].0, tokens[0].1);
    john_client
        .request_with_headers(
            "DELETE",
            &format!("{locks}/"),
            [("if", one_token.as_str())],
            "",
        )
        .await
        .with_status(StatusCode::LOCKED);
    john_client
        .request_with_headers(
            "MOVE",
            &tokens[1].0,
            [
                ("destination", tokens[0].0.as_str()),
                ("overwrite", "T"),
                (
                    "if",
                    format!("<{}> (<{}>)", tokens[1].0, tokens[1].1).as_str(),
                ),
            ],
            "",
        )
        .await
        .with_status(StatusCode::LOCKED);
    for (path, token) in &tokens {
        john_client
            .unlock(path, token)
            .await
            .with_status(StatusCode::NO_CONTENT);
    }
    let dir_token = john_client
        .lock_create(&locks, "owner", true, "infinity", "Second-300")
        .await
        .with_status(StatusCode::CREATED)
        .lock_token()
        .to_string();
    let child = format!("{locks}/new.txt");
    let condition = format!("<{child}> (<{dir_token}>)");
    john_client
        .request_with_headers(
            "PUT",
            &child,
            [("content-type", "text/plain"), ("if", condition.as_str())],
            "x",
        )
        .await
        .with_status(StatusCode::CREATED);
    john_client
        .unlock(&locks, &dir_token)
        .await
        .with_status(StatusCode::NO_CONTENT);

    for path in ["a", "a/b"] {
        john_client
            .request("MKCOL", &format!("{root}/{path}"), "")
            .await
            .with_status(StatusCode::CREATED);
    }
    for method in ["MOVE", "COPY"] {
        john_client
            .request_with_headers(
                method,
                &format!("{root}/a/"),
                [("destination", format!("{root}/a/b/c/").as_str())],
                "",
            )
            .await
            .with_status(StatusCode::FORBIDDEN);
    }

    share(
        john,
        shared_id,
        json!({&jane_id: {"mayRead": true, "mayRename": true, "mayAddChildren": true}}),
    )
    .await;
    put_text(&jane_client, &format!("{shared}/doc.txt"), "sharee")
        .await
        .with_status(StatusCode::FORBIDDEN);
    share(
        john,
        shared_id,
        json!({&jane_id: {"mayRead": true, "mayRename": true, "mayAddChildren": true, "mayModifyContent": true}}),
    )
    .await;
    put_text(&jane_client, &format!("{shared}/doc.txt"), "sharee")
        .await
        .with_status(StatusCode::NO_CONTENT);

    jane_client
        .request("MKCOL", &format!("{JANE_BASE}/mine"), "")
        .await
        .with_status(StatusCode::CREATED);
    put_text(&jane_client, &format!("{JANE_BASE}/mine/mine.txt"), "mine")
        .await
        .with_status(StatusCode::CREATED);

    share(
        john,
        shared_id,
        json!({&jane_id: {"mayRead": true, "mayRename": true, "mayModifyContent": true}}),
    )
    .await;
    let copy_into_shared = [("destination", format!("{shared}/copied.txt"))];
    raw_request(
        &jane_client,
        "COPY",
        &format!("{JANE_BASE}/mine/mine.txt"),
        &copy_into_shared,
    )
    .await
    .with_status(StatusCode::FORBIDDEN);
    share(
        john,
        shared_id,
        json!({&jane_id: {"mayRead": true, "mayRename": true, "mayAddChildren": true, "mayModifyContent": true}}),
    )
    .await;
    raw_request(
        &jane_client,
        "COPY",
        &format!("{JANE_BASE}/mine/mine.txt"),
        &copy_into_shared,
    )
    .await
    .with_status(StatusCode::CREATED);

    let move_out = [("destination", format!("{shared}/sub/doc.txt"))];
    raw_request(
        &jane_client,
        "MOVE",
        &format!("{shared}/doc.txt"),
        &move_out,
    )
    .await
    .with_status(StatusCode::FORBIDDEN);
    share(
        john,
        shared_id,
        json!({&jane_id: {"mayRead": true, "mayRename": true, "mayAddChildren": true, "mayModifyContent": true, "mayDelete": true}}),
    )
    .await;
    share(
        john,
        doc_id,
        json!({&jane_id: {"mayRead": true, "mayRename": true}}),
    )
    .await;
    raw_request(
        &jane_client,
        "MOVE",
        &format!("{shared}/doc.txt"),
        &move_out,
    )
    .await
    .with_status(StatusCode::CREATED);

    share(john, inner_id, json!({&jane_id: {"mayRead": true}})).await;
    let overwrite_keep = [("destination", format!("{shared}/keep/"))];
    raw_request(
        &jane_client,
        "COPY",
        &format!("{JANE_BASE}/mine/"),
        &overwrite_keep,
    )
    .await
    .with_status(StatusCode::FORBIDDEN);
    jane_client
        .request("DELETE", &format!("{shared}/keep/"), "")
        .await
        .with_status(StatusCode::FORBIDDEN);
    share(john, inner_id, Value::Null).await;
    raw_request(
        &jane_client,
        "COPY",
        &format!("{JANE_BASE}/mine/"),
        &overwrite_keep,
    )
    .await
    .with_status(StatusCode::NO_CONTENT);

    share(
        john,
        proj_id,
        json!({&jane_id: {"mayRead": true}, &bill_id: {"mayRead": true}}),
    )
    .await;
    raw_request(
        &jane_client,
        "COPY",
        &format!("{root}/proj/"),
        &[("destination", format!("{JANE_BASE}/proj-copy/"))],
    )
    .await
    .with_status(StatusCode::CREATED);
    assert_eq!(
        share_with_by_name(jane, "proj-copy").await,
        Value::Null,
        "copied folder must not carry shares"
    );
    let bill_response = bill_client
        .request("GET", &format!("{JANE_BASE}/proj-copy/x.txt"), "")
        .await;
    assert_ne!(
        bill_response.status,
        StatusCode::OK,
        "a sharee of the source must not read the copy"
    );

    let state = account_state(john).await;
    share(john, target_id, json!({&jane_id: {"mayRead": true}})).await;
    john_client
        .request_with_headers(
            "MOVE",
            &format!("{root}/moving/"),
            [("destination", format!("{root}/target/moving/").as_str())],
            "",
        )
        .await
        .with_status(StatusCode::CREATED);
    let changed = sharee_changes(jane, john, &state).await;
    for id in [moving_id, moving_file_id, deeper_id, deeper_file_id] {
        assert!(
            changed.contains(id),
            "{id} missing from changes {changed:?}"
        );
    }

    for path in ["mine/", "proj-copy/"] {
        jane_client
            .request("DELETE", &format!("{JANE_BASE}/{path}"), "")
            .await
            .with_status(StatusCode::NO_CONTENT);
    }
    destroy_tree(john, root_id).await;
    test.assert_is_empty().await;
}

async fn put_text(client: &DummyWebDavClient, path: &str, contents: &str) -> DavResponse {
    client
        .request_with_headers("PUT", path, [("content-type", "text/plain")], contents)
        .await
}

async fn raw_request(
    client: &DummyWebDavClient,
    method: &str,
    path: &str,
    headers: &[(&'static str, String)],
) -> DavResponse {
    let mut request = reqwest::Client::builder()
        .timeout(Duration::from_millis(500))
        .danger_accept_invalid_certs(true)
        .build()
        .expect("http client")
        .request(
            Method::from_bytes(method.as_bytes()).expect("method"),
            format!("https://127.0.0.1:8899{path}"),
        )
        .header(AUTHORIZATION, client.credentials.as_str());
    for (key, value) in headers {
        request = request.header(*key, value.as_str());
    }
    let response = request.send().await.expect("request");
    DavResponse {
        status: response.status(),
        headers: Default::default(),
        body: response.text().await.map_err(|err| err.to_string()),
        xml: Vec::new(),
    }
}

async fn share(owner: &Account, id: &str, share_with: Value) {
    owner
        .jmap_update(
            MethodObject::FileNode,
            [(id, json!({"shareWith": share_with}))],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .updated(id);
}

async fn share_with_by_name(account: &Account, name: &str) -> Value {
    account
        .jmap_method_calls(json!([
            [
                "FileNode/query",
                {"accountId": account.id_string(), "filter": {"name": name}},
                "0"
            ],
            [
                "FileNode/get",
                {
                    "accountId": account.id_string(),
                    "#ids": {"resultOf": "0", "name": "FileNode/query", "path": "/ids"},
                    "properties": ["shareWith"]
                },
                "1"
            ]
        ]))
        .await
        .pointer("/methodResponses/1/1/list/0/shareWith")
        .cloned()
        .unwrap_or_else(|| panic!("{name} not found"))
}

async fn account_state(account: &Account) -> String {
    account
        .jmap_method_calls(json!([[
            "FileNode/get",
            {"accountId": account.id_string(), "ids": []},
            "0"
        ]]))
        .await
        .pointer("/methodResponses/0/1/state")
        .and_then(Value::as_str)
        .expect("state")
        .to_string()
}

async fn sharee_changes(sharee: &Account, owner: &Account, state: &str) -> AHashSet<String> {
    let changes = sharee
        .jmap_method_calls(json!([[
            "FileNode/changes",
            {"accountId": owner.id_string(), "sinceState": state},
            "0"
        ]]))
        .await;
    ["created", "updated"]
        .iter()
        .flat_map(|kind| {
            changes
                .pointer(&format!("/methodResponses/0/1/{kind}"))
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_string)
        })
        .collect()
}

async fn upload_blob(account: &Account, contents: &str) -> String {
    account
        .jmap_method_calls(json!([[
            "Blob/upload",
            {
                "accountId": account.id_string(),
                "create": {"b": {"data": [{"data:asText": contents}]}}
            },
            "0"
        ]]))
        .await
        .pointer("/methodResponses/0/1/created/b/id")
        .and_then(Value::as_str)
        .expect("blob upload")
        .to_string()
}

async fn destroy_tree(account: &Account, id: &str) {
    account
        .jmap_destroy(
            MethodObject::FileNode,
            [id],
            [("onDestroyRemoveChildren", true)],
        )
        .await
        .destroyed()
        .for_each(drop);
}
