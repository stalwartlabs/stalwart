/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    store::deflate_test_resource,
    utils::server::{DestroyAllMailboxes, TestServer},
};
use ::email::{
    cache::MessageCacheFetch,
    mailbox::INBOX_ID,
    message::ingest::{EmailIngest, IngestEmail, IngestSource},
};
use common::auth::AccessToken;
use jmap_client::{email, mailbox::Role};
use mail_parser::{MessageParser, mailbox::mbox::MessageIterator};
use std::{io::Cursor, str::FromStr, time::Duration};
use store::{
    ahash::AHashSet,
    rand::{self, Rng},
};
use types::id::Id;

pub async fn test(test: &TestServer) {
    test_single_thread(test).await;
    test_multi_thread(test).await;
}

async fn test_single_thread(test_server: &TestServer) {
    println!("Running Email Merge Threads tests...");
    let account = test_server.account("admin@example.com");
    let mut client = account.jmap_client().await;

    let mut account_ids = Vec::new();
    for name in [
        "admin@example.com",
        "jdoe@example.com",
        "jane.smith@example.com",
        "bill@example.com",
        "robert@example.com",
        "sales@example.com",
    ] {
        account_ids.push(test_server.account(name).id_string());
    }

    for (test_group_num, test) in [test_1(), test_2(), test_3()].iter().enumerate() {
        let mut messages = Vec::new();
        let mut total_messages = 0;
        let mut messages_per_thread =
            build_messages(test, &mut messages, &mut total_messages, None, 0);
        messages_per_thread.sort_unstable();

        let mut mailbox_ids = Vec::with_capacity(6);

        for account_id in &account_ids {
            mailbox_ids.push(
                client
                    .set_default_account_id(*account_id)
                    .mailbox_create("Thread nightmare", None::<String>, Role::None)
                    .await
                    .unwrap()
                    .take_id(),
            );
        }

        for message in &messages {
            client
                .set_default_account_id(account_ids[0])
                .email_import(
                    message.to_string().into_bytes(),
                    [mailbox_ids[0].clone()],
                    None::<Vec<String>>,
                    None,
                )
                .await
                .unwrap();
        }

        for message in messages.iter().rev() {
            client
                .set_default_account_id(account_ids[1])
                .email_import(
                    message.to_string().into_bytes(),
                    [mailbox_ids[1].clone()],
                    None::<Vec<String>>,
                    None,
                )
                .await
                .unwrap();
        }

        for chunk in messages.chunks(5) {
            client.set_default_account_id(account_ids[2]);
            for message in chunk {
                client
                    .email_import(
                        message.to_string().into_bytes(),
                        [mailbox_ids[2].clone()],
                        None::<Vec<String>>,
                        None,
                    )
                    .await
                    .unwrap();
            }

            client.set_default_account_id(account_ids[3]);
            for message in chunk.iter().rev() {
                client
                    .email_import(
                        message.to_string().into_bytes(),
                        [mailbox_ids[3].clone()],
                        None::<Vec<String>>,
                        None,
                    )
                    .await
                    .unwrap();
            }
        }

        for chunk in messages.chunks(5).rev() {
            client.set_default_account_id(account_ids[4]);
            for message in chunk {
                client
                    .email_import(
                        message.to_string().into_bytes(),
                        [mailbox_ids[4].clone()],
                        None::<Vec<String>>,
                        None,
                    )
                    .await
                    .unwrap();
            }

            client.set_default_account_id(account_ids[5]);
            for message in chunk.iter().rev() {
                client
                    .email_import(
                        message.to_string().into_bytes(),
                        [mailbox_ids[5].clone()],
                        None::<Vec<String>>,
                        None,
                    )
                    .await
                    .unwrap();
            }
        }
        test_server.wait_for_tasks().await;

        for test_num in 0..=5 {
            let result = client
                .set_default_account_id(account_ids[test_num])
                .email_query(
                    email::query::Filter::in_mailbox(mailbox_ids[test_num].clone()).into(),
                    None::<Vec<_>>,
                )
                .await
                .unwrap();

            assert_eq!(
                result.ids().len(),
                total_messages,
                "test# {}/{}",
                test_group_num,
                test_num
            );

            let thread_ids: AHashSet<u32> = result
                .ids()
                .iter()
                .map(|id| Id::from_str(id).unwrap().prefix_id())
                .collect();

            let mut messages_per_thread_db = Vec::new();

            for thread_id in thread_ids {
                messages_per_thread_db.push(
                    client
                        .thread_get(&Id::new(thread_id as u64).to_string())
                        .await
                        .unwrap()
                        .unwrap()
                        .email_ids()
                        .len(),
                );
            }
            messages_per_thread_db.sort_unstable();

            assert_eq!(messages_per_thread_db, messages_per_thread);
            println!("passed test# {}/{}", test_group_num, test_num);
        }

        for account_id in &account_ids {
            client
                .set_default_account_id(*account_id)
                .destroy_all_mailboxes()
                .await;
        }
        test_server.wait_for_tasks().await;
        test_server.assert_is_empty().await;
    }

    test_server.assert_is_empty().await;
}

#[allow(dead_code)]
async fn test_multi_thread(test: &TestServer) {
    println!("Running Email Merge Threads tests (multi-threaded)...");
    let mut handles = vec![];
    let account = test.account("jdoe@example.com");
    let account_id = account.id().document_id();
    let mailbox_id = INBOX_ID;

    for message in MessageIterator::new(Cursor::new(deflate_test_resource("mailbox.gz")))
        .collect::<Vec<_>>()
        .into_iter()
    {
        let message = message.unwrap();
        let server = test.server.clone();
        handles.push(tokio::task::spawn(async move {
            let mut retry_count = 0;
            loop {
                match server
                    .email_ingest(IngestEmail {
                        raw_message: message.contents(),
                        message: MessageParser::new().parse(message.contents()),
                        blob_hash: None,
                        access_token: &AccessToken::from_id_maybe_invalid(account_id),
                        mailbox_ids: vec![mailbox_id],
                        keywords: vec![],
                        received_at: None,
                        source: IngestSource::Smtp {
                            deliver_to: "test@domain.org",
                            is_sender_authenticated: true,
                            is_spam: false,
                        },
                        session_id: 0,
                    })
                    .await
                {
                    Ok(_) => break,
                    Err(err) => {
                        if err.is_assertion_failure() && retry_count < 10 {
                            //println!("Retrying ingest for {}...", message.from());
                            let backoff = rand::rng().random_range(50..=300);
                            tokio::time::sleep(Duration::from_millis(backoff)).await;
                            retry_count += 1;
                            continue;
                        }
                        panic!("Failed to ingest message: {:?}", err);
                    }
                }
            }
        }));
    }
    // Wait for all tasks to complete
    let messages = handles.len();
    println!("Waiting for {} tasks to complete...", messages);
    for handle in handles {
        handle.await.expect("Task panicked");
    }
    assert_eq!(
        messages,
        test.server
            .get_cached_messages(account_id)
            .await
            .unwrap()
            .emails
            .items
            .len(),
    );
    println!("Deleting all messages...");
    test.destroy_all_mailboxes(account).await;
    test.assert_is_empty().await;
}

fn build_message(message: usize, in_reply_to: Option<usize>, thread_num: usize) -> String {
    if let Some(in_reply_to) = in_reply_to {
        format!(
            "Message-ID: <{}>\nReferences: <{}>\nSubject: re: T{}\n\nreply\n",
            message, in_reply_to, thread_num
        )
    } else {
        format!(
            "Message-ID: <{}>\nSubject: T{}\n\nmsg\n",
            message, thread_num
        )
    }
}

fn build_messages(
    three: &ThreadTest,
    messages: &mut Vec<String>,
    total_messages: &mut usize,
    in_reply_to: Option<usize>,
    thread_num: usize,
) -> Vec<usize> {
    let mut messages_per_thread = Vec::new();
    match three {
        ThreadTest::Message => {
            *total_messages += 1;
            messages.push(build_message(*total_messages, in_reply_to, thread_num));
        }
        ThreadTest::MessageWithReplies(replies) => {
            *total_messages += 1;
            messages.push(build_message(*total_messages, in_reply_to, thread_num));
            let in_reply_to = Some(*total_messages);
            for reply in replies {
                build_messages(reply, messages, total_messages, in_reply_to, thread_num);
            }
        }
        ThreadTest::Root(items) => {
            for (thread_num, item) in items.iter().enumerate() {
                let count_start = *total_messages;
                build_messages(item, messages, total_messages, None, thread_num);
                messages_per_thread.push(*total_messages - count_start);
            }
        }
    }
    messages_per_thread
}

pub fn build_thread_test_messages() -> Vec<String> {
    let mut messages = Vec::new();
    let mut total_messages = 0;
    build_messages(&test_3(), &mut messages, &mut total_messages, None, 0);
    messages
}

pub enum ThreadTest {
    Message,
    MessageWithReplies(Vec<ThreadTest>),
    Root(Vec<ThreadTest>),
}

fn test_1() -> ThreadTest {
    ThreadTest::Root(vec![
        ThreadTest::Message,
        ThreadTest::MessageWithReplies(vec![
            ThreadTest::Message,
            ThreadTest::MessageWithReplies(vec![ThreadTest::Message]),
            ThreadTest::MessageWithReplies(vec![
                ThreadTest::Message,
                ThreadTest::MessageWithReplies(vec![
                    ThreadTest::Message,
                    ThreadTest::Message,
                    ThreadTest::MessageWithReplies(vec![
                        ThreadTest::Message,
                        ThreadTest::MessageWithReplies(vec![
                            ThreadTest::Message,
                            ThreadTest::Message,
                            ThreadTest::Message,
                        ]),
                    ]),
                    ThreadTest::MessageWithReplies(vec![
                        ThreadTest::Message,
                        ThreadTest::MessageWithReplies(vec![
                            ThreadTest::Message,
                            ThreadTest::Message,
                            ThreadTest::Message,
                            ThreadTest::Message,
                            ThreadTest::MessageWithReplies(vec![
                                ThreadTest::Message,
                                ThreadTest::MessageWithReplies(vec![
                                    ThreadTest::Message,
                                    ThreadTest::Message,
                                    ThreadTest::MessageWithReplies(vec![ThreadTest::Message]),
                                ]),
                                ThreadTest::MessageWithReplies(vec![
                                    ThreadTest::Message,
                                    ThreadTest::Message,
                                ]),
                            ]),
                        ]),
                    ]),
                ]),
            ]),
        ]),
    ])
}

fn test_2() -> ThreadTest {
    ThreadTest::Root(vec![
        ThreadTest::MessageWithReplies(vec![
            ThreadTest::Message,
            ThreadTest::Message,
            ThreadTest::Message,
            ThreadTest::MessageWithReplies(vec![
                ThreadTest::MessageWithReplies(vec![
                    ThreadTest::Message,
                    ThreadTest::MessageWithReplies(vec![
                        ThreadTest::MessageWithReplies(vec![
                            ThreadTest::MessageWithReplies(vec![
                                ThreadTest::MessageWithReplies(vec![
                                    ThreadTest::MessageWithReplies(vec![
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::MessageWithReplies(vec![
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                            ]),
                                            ThreadTest::MessageWithReplies(vec![
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                            ]),
                                            ThreadTest::MessageWithReplies(vec![
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                            ]),
                                        ]),
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::MessageWithReplies(vec![
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                            ]),
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                        ]),
                                        ThreadTest::Message,
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::Message,
                                            ThreadTest::MessageWithReplies(vec![
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                            ]),
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                        ]),
                                    ]),
                                    ThreadTest::Message,
                                ]),
                                ThreadTest::Message,
                            ]),
                            ThreadTest::Message,
                        ]),
                        ThreadTest::Message,
                    ]),
                    ThreadTest::MessageWithReplies(vec![
                        ThreadTest::MessageWithReplies(vec![
                            ThreadTest::MessageWithReplies(vec![ThreadTest::MessageWithReplies(
                                vec![
                                    ThreadTest::MessageWithReplies(vec![
                                        ThreadTest::Message,
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::MessageWithReplies(vec![
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                            ]),
                                            ThreadTest::MessageWithReplies(vec![
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                            ]),
                                            ThreadTest::Message,
                                        ]),
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::Message,
                                            ThreadTest::MessageWithReplies(vec![
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                            ]),
                                            ThreadTest::MessageWithReplies(vec![
                                                ThreadTest::Message,
                                            ]),
                                        ]),
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::MessageWithReplies(vec![
                                                ThreadTest::Message,
                                            ]),
                                            ThreadTest::Message,
                                        ]),
                                    ]),
                                    ThreadTest::Message,
                                    ThreadTest::Message,
                                    ThreadTest::MessageWithReplies(vec![
                                        ThreadTest::Message,
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::Message,
                                            ThreadTest::MessageWithReplies(vec![
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                            ]),
                                        ]),
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::Message,
                                            ThreadTest::MessageWithReplies(vec![
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                            ]),
                                        ]),
                                    ]),
                                ],
                            )]),
                            ThreadTest::Message,
                        ]),
                        ThreadTest::Message,
                        ThreadTest::MessageWithReplies(vec![ThreadTest::MessageWithReplies(vec![
                            ThreadTest::Message,
                            ThreadTest::MessageWithReplies(vec![
                                ThreadTest::MessageWithReplies(vec![
                                    ThreadTest::MessageWithReplies(vec![
                                        ThreadTest::MessageWithReplies(vec![ThreadTest::Message]),
                                    ]),
                                ]),
                                ThreadTest::MessageWithReplies(vec![ThreadTest::Message]),
                                ThreadTest::MessageWithReplies(vec![
                                    ThreadTest::MessageWithReplies(vec![
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                        ]),
                                        ThreadTest::Message,
                                        ThreadTest::Message,
                                        ThreadTest::Message,
                                    ]),
                                    ThreadTest::MessageWithReplies(vec![ThreadTest::Message]),
                                    ThreadTest::Message,
                                    ThreadTest::MessageWithReplies(vec![
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                        ]),
                                    ]),
                                ]),
                                ThreadTest::MessageWithReplies(vec![
                                    ThreadTest::MessageWithReplies(vec![ThreadTest::Message]),
                                ]),
                            ]),
                            ThreadTest::Message,
                            ThreadTest::Message,
                        ])]),
                    ]),
                ]),
                ThreadTest::Message,
                ThreadTest::MessageWithReplies(vec![
                    ThreadTest::MessageWithReplies(vec![
                        ThreadTest::MessageWithReplies(vec![
                            ThreadTest::Message,
                            ThreadTest::Message,
                        ]),
                        ThreadTest::MessageWithReplies(vec![
                            ThreadTest::Message,
                            ThreadTest::MessageWithReplies(vec![
                                ThreadTest::MessageWithReplies(vec![
                                    ThreadTest::MessageWithReplies(vec![ThreadTest::Message]),
                                ]),
                                ThreadTest::MessageWithReplies(vec![
                                    ThreadTest::Message,
                                    ThreadTest::MessageWithReplies(vec![
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::MessageWithReplies(vec![
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                            ]),
                                            ThreadTest::Message,
                                            ThreadTest::MessageWithReplies(vec![
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                            ]),
                                            ThreadTest::Message,
                                        ]),
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::MessageWithReplies(vec![
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                            ]),
                                        ]),
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::Message,
                                            ThreadTest::MessageWithReplies(vec![
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                            ]),
                                        ]),
                                    ]),
                                    ThreadTest::Message,
                                ]),
                            ]),
                            ThreadTest::MessageWithReplies(vec![
                                ThreadTest::MessageWithReplies(vec![
                                    ThreadTest::Message,
                                    ThreadTest::MessageWithReplies(vec![
                                        ThreadTest::Message,
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                            ThreadTest::MessageWithReplies(vec![
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                            ]),
                                        ]),
                                        ThreadTest::Message,
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                        ]),
                                    ]),
                                ]),
                                ThreadTest::MessageWithReplies(vec![
                                    ThreadTest::MessageWithReplies(vec![
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                        ]),
                                    ]),
                                ]),
                                ThreadTest::Message,
                                ThreadTest::Message,
                            ]),
                        ]),
                        ThreadTest::Message,
                        ThreadTest::MessageWithReplies(vec![
                            ThreadTest::MessageWithReplies(vec![ThreadTest::Message]),
                            ThreadTest::MessageWithReplies(vec![
                                ThreadTest::MessageWithReplies(vec![
                                    ThreadTest::Message,
                                    ThreadTest::Message,
                                    ThreadTest::Message,
                                ]),
                                ThreadTest::Message,
                                ThreadTest::Message,
                                ThreadTest::MessageWithReplies(vec![
                                    ThreadTest::MessageWithReplies(vec![
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::MessageWithReplies(vec![
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                            ]),
                                            ThreadTest::Message,
                                            ThreadTest::MessageWithReplies(vec![
                                                ThreadTest::Message,
                                            ]),
                                            ThreadTest::Message,
                                        ]),
                                        ThreadTest::Message,
                                        ThreadTest::Message,
                                    ]),
                                    ThreadTest::Message,
                                    ThreadTest::Message,
                                ]),
                            ]),
                            ThreadTest::Message,
                            ThreadTest::Message,
                        ]),
                    ]),
                    ThreadTest::Message,
                    ThreadTest::Message,
                ]),
            ]),
        ]),
        ThreadTest::Message,
        ThreadTest::MessageWithReplies(vec![ThreadTest::Message, ThreadTest::Message]),
    ])
}

fn test_3() -> ThreadTest {
    ThreadTest::Root(vec![
        ThreadTest::MessageWithReplies(vec![ThreadTest::Message, ThreadTest::Message]),
        ThreadTest::Message,
        ThreadTest::MessageWithReplies(vec![
            ThreadTest::MessageWithReplies(vec![
                ThreadTest::MessageWithReplies(vec![
                    ThreadTest::Message,
                    ThreadTest::Message,
                    ThreadTest::Message,
                ]),
                ThreadTest::Message,
                ThreadTest::MessageWithReplies(vec![ThreadTest::Message]),
                ThreadTest::Message,
            ]),
            ThreadTest::Message,
            ThreadTest::Message,
        ]),
        ThreadTest::Message,
        ThreadTest::MessageWithReplies(vec![
            ThreadTest::MessageWithReplies(vec![ThreadTest::Message]),
            ThreadTest::MessageWithReplies(vec![
                ThreadTest::Message,
                ThreadTest::MessageWithReplies(vec![ThreadTest::MessageWithReplies(vec![
                    ThreadTest::Message,
                    ThreadTest::MessageWithReplies(vec![
                        ThreadTest::MessageWithReplies(vec![ThreadTest::MessageWithReplies(vec![
                            ThreadTest::MessageWithReplies(vec![ThreadTest::MessageWithReplies(
                                vec![ThreadTest::MessageWithReplies(vec![
                                    ThreadTest::Message,
                                    ThreadTest::Message,
                                ])],
                            )]),
                            ThreadTest::Message,
                            ThreadTest::Message,
                        ])]),
                        ThreadTest::MessageWithReplies(vec![
                            ThreadTest::Message,
                            ThreadTest::MessageWithReplies(vec![
                                ThreadTest::Message,
                                ThreadTest::MessageWithReplies(vec![ThreadTest::Message]),
                                ThreadTest::MessageWithReplies(vec![
                                    ThreadTest::MessageWithReplies(vec![
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                        ]),
                                        ThreadTest::MessageWithReplies(vec![ThreadTest::Message]),
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                        ]),
                                        ThreadTest::Message,
                                    ]),
                                    ThreadTest::MessageWithReplies(vec![
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                        ]),
                                        ThreadTest::Message,
                                    ]),
                                ]),
                            ]),
                        ]),
                    ]),
                    ThreadTest::Message,
                    ThreadTest::Message,
                ])]),
                ThreadTest::Message,
            ]),
            ThreadTest::MessageWithReplies(vec![
                ThreadTest::Message,
                ThreadTest::MessageWithReplies(vec![ThreadTest::MessageWithReplies(vec![
                    ThreadTest::Message,
                ])]),
                ThreadTest::Message,
            ]),
        ]),
        ThreadTest::MessageWithReplies(vec![
            ThreadTest::MessageWithReplies(vec![ThreadTest::MessageWithReplies(vec![
                ThreadTest::Message,
                ThreadTest::MessageWithReplies(vec![ThreadTest::Message, ThreadTest::Message]),
                ThreadTest::Message,
                ThreadTest::Message,
            ])]),
            ThreadTest::MessageWithReplies(vec![
                ThreadTest::MessageWithReplies(vec![
                    ThreadTest::MessageWithReplies(vec![
                        ThreadTest::Message,
                        ThreadTest::Message,
                        ThreadTest::Message,
                        ThreadTest::Message,
                    ]),
                    ThreadTest::MessageWithReplies(vec![ThreadTest::MessageWithReplies(vec![
                        ThreadTest::MessageWithReplies(vec![
                            ThreadTest::Message,
                            ThreadTest::MessageWithReplies(vec![ThreadTest::MessageWithReplies(
                                vec![
                                    ThreadTest::Message,
                                    ThreadTest::Message,
                                    ThreadTest::MessageWithReplies(vec![
                                        ThreadTest::Message,
                                        ThreadTest::Message,
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                        ]),
                                    ]),
                                    ThreadTest::Message,
                                ],
                            )]),
                            ThreadTest::Message,
                            ThreadTest::MessageWithReplies(vec![ThreadTest::MessageWithReplies(
                                vec![
                                    ThreadTest::Message,
                                    ThreadTest::MessageWithReplies(vec![ThreadTest::Message]),
                                ],
                            )]),
                        ]),
                        ThreadTest::MessageWithReplies(vec![
                            ThreadTest::Message,
                            ThreadTest::Message,
                        ]),
                    ])]),
                    ThreadTest::MessageWithReplies(vec![ThreadTest::Message]),
                    ThreadTest::Message,
                ]),
                ThreadTest::MessageWithReplies(vec![ThreadTest::Message]),
                ThreadTest::Message,
            ]),
        ]),
        ThreadTest::MessageWithReplies(vec![
            ThreadTest::Message,
            ThreadTest::MessageWithReplies(vec![
                ThreadTest::MessageWithReplies(vec![
                    ThreadTest::MessageWithReplies(vec![
                        ThreadTest::MessageWithReplies(vec![
                            ThreadTest::MessageWithReplies(vec![
                                ThreadTest::MessageWithReplies(vec![
                                    ThreadTest::MessageWithReplies(vec![
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                            ThreadTest::MessageWithReplies(vec![
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                            ]),
                                        ]),
                                        ThreadTest::Message,
                                    ]),
                                    ThreadTest::Message,
                                    ThreadTest::Message,
                                ]),
                                ThreadTest::Message,
                                ThreadTest::Message,
                                ThreadTest::Message,
                            ]),
                            ThreadTest::Message,
                        ]),
                        ThreadTest::Message,
                    ]),
                    ThreadTest::Message,
                ]),
                ThreadTest::MessageWithReplies(vec![
                    ThreadTest::Message,
                    ThreadTest::MessageWithReplies(vec![
                        ThreadTest::Message,
                        ThreadTest::Message,
                        ThreadTest::MessageWithReplies(vec![
                            ThreadTest::Message,
                            ThreadTest::MessageWithReplies(vec![ThreadTest::MessageWithReplies(
                                vec![ThreadTest::Message, ThreadTest::Message],
                            )]),
                            ThreadTest::Message,
                        ]),
                        ThreadTest::Message,
                    ]),
                ]),
            ]),
        ]),
    ])
}
