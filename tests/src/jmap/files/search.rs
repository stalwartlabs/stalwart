/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::properties::{destroy_tree, upload_blob};
use crate::utils::{account::Account, jmap::JmapUtils, server::TestServer};
use ahash::AHashSet;
use encodify::base64::STANDARD;
use jmap_proto::request::method::MethodObject;
use serde_json::{Value, json};
use store::{SearchStore, write::SearchIndex};

const DOCX: &[u8] =
    include_bytes!("../../../../crates/text-extract/tests/fixtures/real/textutil.docx");
const ODT: &[u8] =
    include_bytes!("../../../../crates/text-extract/tests/fixtures/real/textutil.odt");
const PDF: &[u8] = include_bytes!(
    "../../../../crates/text-extract/tests/fixtures/pdf/text/gen/type1-winansi-std14.pdf"
);
const UNTYPED_PDF: &[u8] = include_bytes!(
    "../../../../crates/text-extract/tests/fixtures/pdf/text/gen/actualtext-spans.pdf"
);
const XLSX: &[u8] =
    include_bytes!("../../../../crates/text-extract/tests/fixtures/real/testEXCEL.xlsx");
const PPTX: &[u8] =
    include_bytes!("../../../../crates/text-extract/tests/fixtures/real/testPPT.pptx");
const EPUB: &[u8] =
    include_bytes!("../../../../crates/text-extract/tests/fixtures/real/testEPUB.epub");
const DOCX_TYPE: &str = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
const XLSX_TYPE: &str = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
const PPTX_TYPE: &str = "application/vnd.openxmlformats-officedocument.presentationml.presentation";

pub async fn test(test: &TestServer) {
    println!("Running File Storage content search tests...");
    let account = test.account("jdoe@example.com");

    let docx = upload_binary(account, DOCX).await;
    let odt = upload_binary(account, ODT).await;
    let rtf = upload_blob(
        account,
        "{\\rtf1\\ansi quokka {\\*\\generator hidden}notes\\par}",
    )
    .await;
    let plain = upload_blob(account, "the zebra crossed the road").await;
    let image = upload_binary(account, b"\x89PNG\r\n\x1a\nquokka zebra").await;
    let pdf = upload_binary(account, PDF).await;
    let untyped_pdf = upload_binary(account, UNTYPED_PDF).await;
    let xlsx = upload_binary(account, XLSX).await;
    let pptx = upload_binary(account, PPTX).await;
    let epub = upload_binary(account, EPUB).await;

    let response = account
        .jmap_create(
            MethodObject::FileNode,
            [
                json!({"name": "search"}),
                json!({"name": "report.docx", "parentId": "#i0", "blobId": &docx, "type": DOCX_TYPE}),
                json!({"name": "letter.odt", "parentId": "#i0", "blobId": &odt}),
                json!({"name": "notes.rtf", "parentId": "#i0", "blobId": &rtf, "type": "text/rtf"}),
                json!({"name": "plain.txt", "parentId": "#i0", "blobId": &plain, "type": "text/plain"}),
                json!({"name": "photo.png", "parentId": "#i0", "blobId": &image, "type": "image/png"}),
                json!({"name": "report.pdf", "parentId": "#i0", "blobId": &pdf, "type": "application/pdf"}),
                json!({"name": "scan.pdf", "parentId": "#i0", "blobId": &untyped_pdf}),
                json!({"name": "numbers.xlsx", "parentId": "#i0", "blobId": &xlsx, "type": XLSX_TYPE}),
                json!({"name": "slides.pptx", "parentId": "#i0", "blobId": &pptx, "type": PPTX_TYPE}),
                json!({"name": "book.epub", "parentId": "#i0", "blobId": &epub, "type": "application/epub+zip"}),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let [
        root,
        report,
        letter,
        notes,
        plain_id,
        photo,
        report_pdf,
        scan_pdf,
        numbers,
        slides,
        book,
    ] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10].map(|idx| response.created(idx).id().to_string());
    wait_for_index(test).await;

    for (filter, expected) in [
        (json!({"body": "Stalwart"}), vec![&report, &letter]),
        (json!({"body": "quokka"}), vec![&notes]),
        (json!({"body": "hidden"}), vec![]),
        (json!({"body": "zebra"}), vec![&plain_id]),
        (json!({"text": "zebra"}), vec![&plain_id]),
        (json!({"text": "photo.*"}), vec![&photo]),
        (json!({"text": "image/*"}), vec![&photo]),
        (json!({"body": "Quillbrook"}), vec![&report_pdf]),
        (json!({"body": "Marrowby"}), vec![&report_pdf]),
        (json!({"body": "Oakhollow"}), vec![&scan_pdf]),
        (json!({"body": "Worksheet"}), vec![&numbers]),
        (json!({"body": "Avalanche"}), vec![&slides]),
        (json!({"body": "superchapters"}), vec![&book]),
    ] {
        assert_eq!(
            query(account, filter.clone()).await,
            expected.into_iter().cloned().collect::<AHashSet<_>>(),
            "filter {filter}"
        );
    }

    let giraffe = upload_blob(account, "a giraffe on the savanna").await;
    account
        .jmap_update(
            MethodObject::FileNode,
            [(&plain_id, json!({"blobId": &giraffe}))],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .updated(&plain_id);
    wait_for_index(test).await;
    assert!(query(account, json!({"body": "zebra"})).await.is_empty());
    assert_eq!(
        query(account, json!({"body": "giraffe"})).await,
        [plain_id.clone()].into_iter().collect()
    );

    account
        .jmap_update(
            MethodObject::FileNode,
            [(&report, json!({"blobId": &image, "type": "image/png"}))],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .updated(&report);
    wait_for_index(test).await;
    assert_eq!(
        query(account, json!({"body": "Stalwart"})).await,
        [letter.clone()].into_iter().collect(),
        "report={report} letter={letter} notes={notes} plain={plain_id} photo={photo}"
    );

    let wombat = upload_blob(account, "a wombat in the burrow").await;
    let response = account
        .jmap_create(
            MethodObject::FileNode,
            [
                json!({"name": "notes.txt", "parentId": &root, "blobId": &wombat}),
                json!({"name": "wombat.bin", "parentId": &root, "blobId": &wombat,
                       "type": "application/octet-stream"}),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let [untyped, binary] = [0, 1].map(|idx| response.created(idx).id().to_string());
    wait_for_index(test).await;
    assert_eq!(
        query(account, json!({"body": "wombat"})).await,
        [untyped.clone()].into_iter().collect()
    );

    account
        .jmap_update(
            MethodObject::FileNode,
            [(&binary, json!({"type": "text/plain"}))],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .updated(&binary);
    account
        .jmap_update(
            MethodObject::FileNode,
            [(&untyped, json!({"name": "notes.dat"}))],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .updated(&untyped);
    wait_for_index(test).await;
    assert_eq!(
        query(account, json!({"body": "wombat"})).await,
        [binary.clone()].into_iter().collect()
    );

    destroy_tree(account, &root).await;
    wait_for_index(test).await;
    test.assert_is_empty().await;
}

async fn wait_for_index(test: &TestServer) {
    test.wait_for_tasks().await;
    if let SearchStore::ElasticSearch(store) = test.server.search_store() {
        store
            .refresh_index(SearchIndex::File)
            .await
            .expect("refresh file index");
    }
}

async fn upload_binary(account: &Account, contents: &[u8]) -> String {
    account
        .jmap_method_calls(json!([[
            "Blob/upload",
            {
                "accountId": account.id_string(),
                "create": {"b": {"data": [{"data:asBase64": STANDARD.encode(contents)}]}}
            },
            "0"
        ]]))
        .await
        .pointer("/methodResponses/0/1/created/b/id")
        .and_then(Value::as_str)
        .expect("blob upload")
        .to_string()
}

async fn query(account: &Account, filter: Value) -> AHashSet<String> {
    let description = filter.to_string();
    account
        .jmap_method_calls(json!([[
            "FileNode/query",
            {"accountId": account.id_string(), "filter": filter},
            "0"
        ]]))
        .await
        .pointer("/methodResponses/0/1/ids")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("query failed for {description}"))
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}
