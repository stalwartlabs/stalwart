/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::server::TestServer;
use email::mailbox::INBOX_ID;
use jmap_client::{client::Client, email::query::Filter};
use mail_builder::MessageBuilder;
use store::{SearchStore, write::SearchIndex};
use types::id::Id;

const PDF: &[u8] = include_bytes!(
    "../../../../crates/text-extract/tests/fixtures/pdf/text/gen/type1-winansi-std14.pdf"
);
const SNIFFED_PDF: &[u8] = include_bytes!(
    "../../../../crates/text-extract/tests/fixtures/pdf/text/gen/actualtext-spans.pdf"
);
const DOCX: &[u8] =
    include_bytes!("../../../../crates/text-extract/tests/fixtures/real/testWORD.docx");
const XLSX: &[u8] =
    include_bytes!("../../../../crates/text-extract/tests/fixtures/real/testEXCEL.xlsx");
const PPTX: &[u8] =
    include_bytes!("../../../../crates/text-extract/tests/fixtures/real/testPPT.pptx");
const ODT: &[u8] =
    include_bytes!("../../../../crates/text-extract/tests/fixtures/real/testOpenOffice2.odt");
const EPUB: &[u8] =
    include_bytes!("../../../../crates/text-extract/tests/fixtures/real/testEPUB.epub");
const RTF: &[u8] =
    include_bytes!("../../../../crates/text-extract/tests/fixtures/real/textutil.rtf");
const PNG: &[u8] = b"\x89PNG\r\n\x1a\npangolin";

const DOCUMENTS: [(&str, &str, &[u8], &str); 8] = [
    ("application/pdf", "report.pdf", PDF, "Quillbrook"),
    ("application/octet-stream", "scan", SNIFFED_PDF, "Oakhollow"),
    (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "document.docx",
        DOCX,
        "subtitle",
    ),
    (
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "numbers.xlsx",
        XLSX,
        "Worksheet",
    ),
    (
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "slides.pptx",
        PPTX,
        "Avalanche",
    ),
    (
        "application/vnd.oasis.opendocument.text",
        "letter.odt",
        ODT,
        "NeoOffice",
    ),
    ("application/epub+zip", "book.epub", EPUB, "superchapters"),
    ("text/rtf", "notes.rtf", RTF, "Stalwart"),
];

const NOT_INDEXED: [&str; 2] = ["pangolin", "Helvetica"];

pub async fn test(test: &TestServer) {
    println!("Running Email attachment search tests...");
    let account = test.account("jdoe@example.com");
    let client = account.jmap_client().await;
    let mailbox_id = Id::from(INBOX_ID).to_string();

    let mut expected = Vec::with_capacity(DOCUMENTS.len());
    for (content_type, file_name, contents, word) in DOCUMENTS {
        let email_id = import(&client, &mailbox_id, content_type, file_name, contents).await;
        expected.push((word, email_id));
    }
    import(&client, &mailbox_id, "image/png", "photo.png", PNG).await;
    wait_for_index(test).await;

    for (word, email_id) in &expected {
        assert_eq!(
            query(&client, word).await,
            [email_id.as_str()],
            "word {word}"
        );
    }
    for word in NOT_INDEXED {
        assert!(query(&client, word).await.is_empty(), "word {word}");
    }

    test.destroy_all_mailboxes(account).await;
    test.assert_is_empty().await;
}

async fn import(
    client: &Client,
    mailbox_id: &str,
    content_type: &str,
    file_name: &str,
    contents: &[u8],
) -> String {
    let raw_message = MessageBuilder::new()
        .from("sender@example.com")
        .to("jdoe@example.com")
        .subject("Document")
        .text_body("See the attached file.")
        .attachment(content_type, file_name, contents)
        .write_to_vec()
        .expect("message builds");
    client
        .email_import(raw_message, [mailbox_id], None::<Vec<&str>>, None)
        .await
        .unwrap_or_else(|err| panic!("import {file_name}: {err}"))
        .take_id()
}

async fn query(client: &Client, word: &str) -> Vec<String> {
    client
        .email_query(Some(Filter::text(word)), None::<Vec<_>>)
        .await
        .unwrap_or_else(|err| panic!("query {word}: {err}"))
        .take_ids()
}

async fn wait_for_index(test: &TestServer) {
    test.wait_for_tasks().await;
    if let SearchStore::ElasticSearch(store) = test.server.search_store() {
        store
            .refresh_index(SearchIndex::Email)
            .await
            .expect("refresh email index");
    }
}
