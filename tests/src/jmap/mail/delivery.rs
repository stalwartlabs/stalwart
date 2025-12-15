/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    directory::internal::TestInternalDirectory,
    imap::antispam::{spam_delete_samples, spam_training_samples},
    jmap::JMAPTest,
    store::cleanup::store_blob_expire_all,
    webdav::DummyWebDavClient,
};
use common::Server;
use email::{
    cache::{MessageCacheFetch, email::MessageCacheAccess},
    mailbox::{INBOX_ID, JUNK_ID, SENT_ID},
    message::metadata::MessageMetadata,
};
use groupware::DavResourceName;
use jmap::blob::download::BlobDownload;
use std::{sync::Arc, time::Duration};
use store::{
    ValueKey,
    roaring::RoaringBitmap,
    write::{AlignedBytes, Archive},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines, ReadHalf, WriteHalf},
    net::TcpStream,
};
use types::{
    blob::{BlobClass, BlobId},
    collection::Collection,
    field::EmailField,
    id::Id,
};
use utils::chained_bytes::ChainedBytes;

pub async fn test(params: &mut JMAPTest) {
    println!("Running message delivery tests...");

    // Enable delivered to
    let old_core = params.server.core.clone();
    let mut new_core = old_core.as_ref().clone();
    new_core.smtp.session.data.add_delivered_to = true;
    params.server.inner.shared_core.store(Arc::new(new_core));

    // Create a domain name and a test account
    let server = params.server.clone();
    let john = params.account("jdoe@example.com");
    let jane = params.account("jane.smith@example.com");
    let bill = params.account("bill@example.com");

    // Create a mailing list
    server
        .store()
        .create_test_list(
            "members@example.com",
            "Mailing List",
            &[
                "jdoe@example.com",
                "jane.smith@example.com",
                "bill@example.com",
            ],
        )
        .await;

    // Delivering to individuals
    let mut lmtp = SmtpConnection::connect().await;
    params.webhook.clear();

    lmtp.ingest(
        "bill@example.com",
        &["jdoe@example.com"],
        concat!(
            "From: bill@example.com\r\n",
            "To: jdoe@example.com\r\n",
            "Subject: TPS Report\r\n",
            "\r\n",
            "I'm going to need those TPS reports ASAP. ",
            "So, if you could do that, that'd be great."
        ),
    )
    .await;

    let john_cache = server
        .get_cached_messages(john.id().document_id())
        .await
        .unwrap();

    assert_eq!(john_cache.emails.items.len(), 1);
    assert_eq!(john_cache.in_mailbox(INBOX_ID).count(), 1);
    assert_eq!(john_cache.in_mailbox(JUNK_ID).count(), 0);

    // Make sure there are no spam training samples
    spam_delete_samples(&params.server).await;
    assert_eq!(spam_training_samples(&params.server).await.total_count, 0);

    // Test spam filtering
    lmtp.ingest(
        "bill@example.com",
        &["john.doe@example.com"],
        concat!(
            "From: bill@example.com\r\n",
            "To: john.doe@example.com\r\n",
            "Subject: XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X\r\n",
            "\r\n",
            "--- Forwarded Message ---\r\n\r\n ",
            "I'm going to need those TPS reports ASAP. ",
            "So, if you could do that, that'd be great."
        ),
    )
    .await;
    let john_cache = server
        .get_cached_messages(john.id().document_id())
        .await
        .unwrap();
    let inbox_ids = john_cache
        .in_mailbox(INBOX_ID)
        .map(|e| e.document_id)
        .collect::<RoaringBitmap>();
    let junk_ids = john_cache
        .in_mailbox(JUNK_ID)
        .map(|e| e.document_id)
        .collect::<RoaringBitmap>();
    assert_eq!(john_cache.emails.items.len(), 2);
    assert_eq!(inbox_ids.len(), 1);
    assert_eq!(junk_ids.len(), 1);
    assert_message_headers_contains(
        &server,
        john.id().document_id(),
        junk_ids.min().unwrap(),
        "X-Spam-Status: Yes",
    )
    .await;
    assert_eq!(spam_training_samples(&params.server).await.total_count, 0);

    // CardDAV spam override
    let dav_client = DummyWebDavClient::new(u32::MAX, john.name(), john.secret(), john.emails()[0]);
    dav_client
        .request(
            "PUT",
            &format!(
                "{}/jdoe%40example.com/default/bill.vcf",
                DavResourceName::Card.base_path()
            ),
            r#"BEGIN:VCARD
VERSION:4.0
FN:Bill Foobar
EMAIL;TYPE=WORK:dmarc-bill@example.com
UID:urn:uuid:e1ee798b-3d4c-41b0-b217-b9c918e4686f
END:VCARD
"#,
        )
        .await
        .with_status(hyper::StatusCode::CREATED);
    lmtp.ingest(
        "dmarc-bill@example.com",
        &["john.doe@example.com"],
        concat!(
            "From: dmarc-bill@example.com\r\n",
            "To: john.doe@example.com\r\n",
            "Subject: XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X\r\n",
            "\r\n",
            "--- Forwarded Message ---\r\n\r\n ",
            "I'm going to need those TPS reports ASAP. ",
            "So, if you could do that, that'd be great."
        ),
    )
    .await;
    let john_cache = server
        .get_cached_messages(john.id().document_id())
        .await
        .unwrap();
    let inbox_ids = john_cache
        .in_mailbox(INBOX_ID)
        .map(|e| e.document_id)
        .collect::<RoaringBitmap>();
    let junk_ids = john_cache
        .in_mailbox(JUNK_ID)
        .map(|e| e.document_id)
        .collect::<RoaringBitmap>();
    assert_eq!(john_cache.emails.items.len(), 3);
    assert_eq!(inbox_ids.len(), 2);
    assert_eq!(junk_ids.len(), 1);
    dav_client.delete_default_containers().await;
    assert_message_headers_contains(
        &server,
        john.id().document_id(),
        inbox_ids.max().unwrap(),
        "X-Spam-Status: No, reason=card-exists",
    )
    .await;
    let samples = spam_training_samples(&params.server).await;
    assert_eq!(samples.ham_count, 1);
    assert_eq!(samples.spam_count, 0);

    // Test trusted reply override
    john.client()
        .email_import(
            concat!(
                "From: john.doe@example.com\r\n",
                "To: dmarc-bill@example.com\r\n",
                "Message-ID: <trusted@message-id.example.com>\r\n",
                "Subject: XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X\r\n",
                "\r\n",
                "This is a trusted reply."
            )
            .as_bytes()
            .to_vec(),
            vec![Id::from(SENT_ID).to_string()],
            None::<Vec<String>>,
            None,
        )
        .await
        .unwrap()
        .take_id();
    assert_eq!(
        server
            .get_cached_messages(john.id().document_id())
            .await
            .unwrap()
            .emails
            .items
            .len(),
        4
    );
    lmtp.ingest(
        "dmarc-bill@example.com",
        &["john.doe@example.com"],
        concat!(
            "From: dmarc-bill@example.com\r\n",
            "To: john.doe@example.com\r\n",
            "Message-ID: <other@message-id.example.com>\r\n",
            "References: <trusted@message-id.example.com>\r\n",
            "Subject: XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X\r\n",
            "\r\n",
            "--- Forwarded Message ---\r\n\r\n ",
            "I'm going to need those TPS reports ASAP. ",
            "So, if you could do that, that'd be great."
        ),
    )
    .await;
    let john_cache = server
        .get_cached_messages(john.id().document_id())
        .await
        .unwrap();
    let inbox_ids = john_cache
        .in_mailbox(INBOX_ID)
        .map(|e| e.document_id)
        .collect::<RoaringBitmap>();
    let junk_ids = john_cache
        .in_mailbox(JUNK_ID)
        .map(|e| e.document_id)
        .collect::<RoaringBitmap>();
    assert_eq!(john_cache.emails.items.len(), 5);
    assert_eq!(inbox_ids.len(), 3);
    assert_eq!(junk_ids.len(), 1);
    assert_message_headers_contains(
        &server,
        john.id().document_id(),
        inbox_ids.max().unwrap(),
        "X-Spam-Status: No, reason=trusted-reply",
    )
    .await;
    let samples = spam_training_samples(&params.server).await;
    assert_eq!(samples.ham_count, 2);
    assert_eq!(samples.spam_count, 0);

    // EXPN and VRFY
    lmtp.expn("members@example.com", 2)
        .await
        .assert_contains("jdoe@example.com")
        .assert_contains("jane.smith@example.com")
        .assert_contains("bill@example.com");
    lmtp.expn("non_existant@example.com", 5).await;
    lmtp.expn("jdoe@example.com", 5).await;
    lmtp.vrfy("jdoe@example.com", 2).await;
    lmtp.vrfy("members@example.com", 5).await;
    lmtp.vrfy("non_existant@example.com", 5).await;

    // Delivering to a mailing list
    lmtp.ingest(
        "bill@example.com",
        &["members@example.com"],
        concat!(
            "From: bill@example.com\r\n",
            "To: members@example.com\r\n",
            "Subject: WFH policy\r\n",
            "\r\n",
            "We need the entire staff back in the office, ",
            "TPS reports cannot be filed properly from home."
        ),
    )
    .await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    for (account, num_messages) in [(john, 6), (jane, 1), (bill, 1)] {
        assert_eq!(
            server
                .get_cached_messages(account.id().document_id())
                .await
                .unwrap()
                .emails
                .items
                .len(),
            num_messages,
            "for {}",
            account.id_string()
        );
    }

    // Removing members from the mailing list and chunked ingest
    params
        .server
        .core
        .storage
        .data
        .remove_from_group("jdoe@example.com", "members@example.com")
        .await;
    lmtp.ingest_chunked(
        "bill@example.com",
        &["members@example.com"],
        concat!(
            "From: bill@example.com\r\n",
            "To: members@example.com\r\n",
            "Subject: WFH policy (reminder)\r\n",
            "\r\n",
            "This is a reminder that we need the entire staff back in the office, ",
            "TPS reports cannot be filed properly from home."
        ),
        10,
    )
    .await;

    for (account, num_messages) in [(john, 6), (jane, 2), (bill, 2)] {
        assert_eq!(
            server
                .get_cached_messages(account.id().document_id())
                .await
                .unwrap()
                .emails
                .items
                .len(),
            num_messages,
            "for {}",
            account.id_string()
        );
    }

    // Deduplication of recipients
    lmtp.ingest(
        "bill@example.com",
        &[
            "members@example.com",
            "jdoe@example.com",
            "john.doe@example.com",
            "jane.smith@example.com",
            "bill@example.com",
        ],
        concat!(
            "From: bill@example.com\r\n",
            "Bcc: Undisclosed recipients;\r\n",
            "Subject: Holidays\r\n",
            "\r\n",
            "Remember to file your TPS reports before ",
            "going on holidays."
        ),
    )
    .await;

    // Make sure blobs are properly linked
    store_blob_expire_all(params.server.store()).await;

    for (account, num_messages) in [(john, 7), (jane, 3), (bill, 3)] {
        let account_id = account.id().document_id();
        let cache = server.get_cached_messages(account_id).await.unwrap();
        assert_eq!(
            cache.emails.items.len(),
            num_messages,
            "for {}",
            account.id_string()
        );
        let access_token = server.get_access_token(account_id).await.unwrap();

        for document_id in cache.in_mailbox(INBOX_ID).map(|e| e.document_id) {
            let metadata = message_metadata(&server, account_id, document_id).await;
            let partial_message = server
                .store()
                .get_blob(metadata.blob_hash.0.as_ref(), 0..usize::MAX)
                .await
                .unwrap()
                .unwrap();
            assert_ne!(metadata.blob_body_offset, 0);
            let expected_full_message = String::from_utf8(
                ChainedBytes::new(metadata.raw_headers.as_ref())
                    .with_last(
                        partial_message
                            .get(metadata.blob_body_offset as usize..)
                            .unwrap_or_default(),
                    )
                    .to_bytes(),
            )
            .unwrap();
            assert!(
                expected_full_message.contains("Delivered-To:")
                    && expected_full_message.contains("Subject:"),
                "for {account_id}: {expected_full_message}"
            );
            let full_message = String::from_utf8(
                server
                    .blob_download(
                        &BlobId {
                            hash: metadata.blob_hash,
                            class: BlobClass::Linked {
                                account_id,
                                collection: Collection::Email.into(),
                                document_id,
                            },
                            section: None,
                        },
                        &access_token,
                    )
                    .await
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(full_message, expected_full_message, "for {account_id}");
        }
    }

    // Remove test data
    for account in [john, jane, bill] {
        params.destroy_all_mailboxes(account).await;
    }
    params.assert_is_empty().await;

    // Restore core
    params.server.inner.shared_core.store(old_core);

    // Check webhook events
    params.webhook.assert_contains(&[
        "message-ingest.",
        "delivery.dsn",
        "\"from\": \"bill@example.com\"",
        "\"john.doe@example.com\"",
    ]);
}

async fn assert_message_headers_contains(
    server: &Server,
    account_id: u32,
    document_id: u32,
    value: &str,
) {
    let headers = message_headers(server, account_id, document_id).await;
    assert!(
        headers.contains(value),
        "Expected message headers to contain {:?}, got {:?}",
        value,
        headers
    );
}

async fn message_headers(server: &Server, account_id: u32, document_id: u32) -> String {
    std::str::from_utf8(
        message_metadata(server, account_id, document_id)
            .await
            .raw_headers
            .as_ref(),
    )
    .unwrap()
    .to_string()
}

async fn message_metadata(server: &Server, account_id: u32, document_id: u32) -> MessageMetadata {
    server
        .store()
        .get_value::<Archive<AlignedBytes>>(ValueKey::property(
            account_id,
            Collection::Email,
            document_id,
            EmailField::Metadata,
        ))
        .await
        .unwrap()
        .unwrap()
        .deserialize::<MessageMetadata>()
        .unwrap()
}

pub struct SmtpConnection {
    reader: Lines<BufReader<ReadHalf<TcpStream>>>,
    writer: WriteHalf<TcpStream>,
}

impl SmtpConnection {
    pub async fn ingest_with_code(
        &mut self,
        from: &str,
        recipients: &[&str],
        message: &str,
        code: u8,
    ) -> Vec<String> {
        self.mail_from(from, 2).await;
        for recipient in recipients {
            self.rcpt_to(recipient, 2).await;
        }
        self.data(3).await;
        let result = self.data_bytes(message, recipients.len(), code).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        result
    }

    pub async fn ingest(&mut self, from: &str, recipients: &[&str], message: &str) {
        self.ingest_with_code(from, recipients, message, 2).await;
    }

    async fn ingest_chunked(
        &mut self,
        from: &str,
        recipients: &[&str],
        message: &str,
        chunk_size: usize,
    ) {
        self.mail_from(from, 2).await;
        for recipient in recipients {
            self.rcpt_to(recipient, 2).await;
        }
        for chunk in message.as_bytes().chunks(chunk_size) {
            self.bdat(std::str::from_utf8(chunk).unwrap(), 2).await;
        }
        self.bdat_last("", recipients.len(), 2).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    pub async fn connect() -> Self {
        SmtpConnection::connect_port(11200).await
    }

    pub async fn connect_port(port: u16) -> Self {
        let (reader, writer) = tokio::io::split(
            TcpStream::connect(&format!("127.0.0.1:{port}"))
                .await
                .unwrap(),
        );
        let mut conn = SmtpConnection {
            reader: BufReader::new(reader).lines(),
            writer,
        };
        conn.read(1, 2).await;
        conn.lhlo().await;
        conn
    }

    pub async fn lhlo(&mut self) -> Vec<String> {
        self.send("LHLO localhost").await;
        self.read(1, 2).await
    }

    pub async fn mail_from(&mut self, sender: &str, code: u8) -> Vec<String> {
        self.send(&format!("MAIL FROM:<{}>", sender)).await;
        self.read(1, code).await
    }

    pub async fn rcpt_to(&mut self, rcpt: &str, code: u8) -> Vec<String> {
        self.send(&format!("RCPT TO:<{}>", rcpt)).await;
        self.read(1, code).await
    }

    pub async fn vrfy(&mut self, rcpt: &str, code: u8) -> Vec<String> {
        self.send(&format!("VRFY {}", rcpt)).await;
        self.read(1, code).await
    }

    pub async fn expn(&mut self, rcpt: &str, code: u8) -> Vec<String> {
        self.send(&format!("EXPN {}", rcpt)).await;
        self.read(1, code).await
    }

    pub async fn data(&mut self, code: u8) -> Vec<String> {
        self.send("DATA").await;
        self.read(1, code).await
    }

    pub async fn data_bytes(
        &mut self,
        message: &str,
        num_responses: usize,
        code: u8,
    ) -> Vec<String> {
        self.send_raw(message).await;
        self.send_raw("\r\n.\r\n").await;
        self.read(num_responses, code).await
    }

    pub async fn bdat(&mut self, chunk: &str, code: u8) -> Vec<String> {
        self.send_raw(&format!("BDAT {}\r\n{}", chunk.len(), chunk))
            .await;
        self.read(1, code).await
    }

    pub async fn bdat_last(&mut self, chunk: &str, num_responses: usize, code: u8) -> Vec<String> {
        self.send_raw(&format!("BDAT {} LAST\r\n{}", chunk.len(), chunk))
            .await;
        self.read(num_responses, code).await
    }

    pub async fn rset(&mut self) -> Vec<String> {
        self.send("RSET").await;
        self.read(1, 2).await
    }

    pub async fn noop(&mut self) -> Vec<String> {
        self.send("NOOP").await;
        self.read(1, 2).await
    }

    pub async fn quit(&mut self) -> Vec<String> {
        self.send("QUIT").await;
        self.read(1, 2).await
    }

    pub async fn read(&mut self, mut num_responses: usize, code: u8) -> Vec<String> {
        let mut lines = Vec::new();
        loop {
            match tokio::time::timeout(Duration::from_millis(1500), self.reader.next_line()).await {
                Ok(Ok(Some(line))) => {
                    let is_done = line.as_bytes()[3] == b' ';
                    //let c = println!("<- {:?}", line);
                    lines.push(line);
                    if is_done {
                        num_responses -= 1;
                        if num_responses != 0 {
                            continue;
                        }

                        if code != u8::MAX {
                            for line in &lines {
                                if line.as_bytes()[0] - b'0' != code {
                                    panic!("Expected completion code {}, got {:?}.", code, lines);
                                }
                            }
                        }
                        return lines;
                    }
                }
                Ok(Ok(None)) => {
                    panic!("Invalid response: {:?}.", lines);
                }
                Ok(Err(err)) => {
                    panic!("Connection broken: {} ({:?})", err, lines);
                }
                Err(_) => panic!("Timeout while waiting for server response: {:?}", lines),
            }
        }
    }

    pub async fn send(&mut self, text: &str) {
        //let c = println!("-> {:?}", text);
        self.writer.write_all(text.as_bytes()).await.unwrap();
        self.writer.write_all(b"\r\n").await.unwrap();
        self.writer.flush().await.unwrap();
    }

    pub async fn send_raw(&mut self, text: &str) {
        //let c = println!("-> {:?}", text);
        self.writer.write_all(text.as_bytes()).await.unwrap();
    }
}

pub trait AssertResult: Sized {
    fn assert_contains(self, text: &str) -> Self;
    fn assert_count(self, text: &str, occurrences: usize) -> Self;
    fn assert_equals(self, text: &str) -> Self;
}

impl AssertResult for Vec<String> {
    fn assert_contains(self, text: &str) -> Self {
        for line in &self {
            if line.contains(text) {
                return self;
            }
        }
        panic!("Expected response to contain {:?}, got {:?}", text, self);
    }

    fn assert_count(self, text: &str, occurrences: usize) -> Self {
        assert_eq!(
            self.iter().filter(|l| l.contains(text)).count(),
            occurrences,
            "Expected {} occurrences of {:?}, found {}.",
            occurrences,
            text,
            self.iter().filter(|l| l.contains(text)).count()
        );
        self
    }

    fn assert_equals(self, text: &str) -> Self {
        for line in &self {
            if line == text {
                return self;
            }
        }
        panic!("Expected response to be {:?}, got {:?}", text, self);
    }
}
