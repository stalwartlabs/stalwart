/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::account::Account;
use crate::utils::jmap::JmapUtils;
use crate::utils::server::{DestroyAllMailboxes, TestServer};
use base64::{Engine, engine::general_purpose};
use chrono::{Duration as ChronoDuration, Utc};
use futures::FutureExt;
use registry::schema::{
    prelude::{ObjectType, Property},
    structs::Action,
};
use serde_json::{Value, json};
use std::cell::RefCell;
use std::collections::HashMap;
use std::future::Future;
use std::panic::AssertUnwindSafe;

pub mod binary;
pub mod core;
pub mod email;
pub mod identity;
pub mod mailbox;
pub mod push;
pub mod search_snippet;
pub mod submission;
pub mod thread;
pub mod vacation;

#[derive(Debug)]
pub enum Fail {
    Assert(String),
    Skip(String),
}

pub type TestOutcome = Result<(), Fail>;

pub fn check(cond: bool, msg: impl std::fmt::Display) -> TestOutcome {
    if cond {
        Ok(())
    } else {
        Err(Fail::Assert(msg.to_string()))
    }
}

pub fn check_eq<T: PartialEq + std::fmt::Debug>(
    actual: T,
    expected: T,
    msg: impl std::fmt::Display,
) -> TestOutcome {
    if actual == expected {
        Ok(())
    } else {
        Err(Fail::Assert(format!(
            "{msg}: expected {expected:?}, got {actual:?}"
        )))
    }
}

pub fn check_ne<T: PartialEq + std::fmt::Debug>(
    actual: T,
    not_expected: T,
    msg: impl std::fmt::Display,
) -> TestOutcome {
    if actual != not_expected {
        Ok(())
    } else {
        Err(Fail::Assert(format!(
            "{msg}: expected value to differ from {not_expected:?}"
        )))
    }
}

pub fn check_contains(haystack: &str, needle: &str, msg: impl std::fmt::Display) -> TestOutcome {
    if haystack.contains(needle) {
        Ok(())
    } else {
        Err(Fail::Assert(format!(
            "{msg}: expected to contain {needle:?}, got {:?}",
            haystack.chars().take(200).collect::<String>()
        )))
    }
}

pub fn skip(reason: impl std::fmt::Display) -> TestOutcome {
    Err(Fail::Skip(reason.to_string()))
}

#[derive(Clone)]
struct Record {
    id: String,
    status: &'static str,
    detail: String,
}

pub struct CompCtx<'x> {
    pub primary: &'x Account,
    pub secondary: &'x Account,
    pub account_id: String,
    pub secondary_account_id: String,
    pub session: Value,
    pub upload_url_tmpl: String,
    pub download_url_tmpl: String,
    pub event_source_url_tmpl: String,
    pub mailbox_ids: HashMap<String, String>,
    pub email_ids: HashMap<String, String>,
    pub blob_ids: HashMap<String, String>,
    pub role_mailboxes: HashMap<String, String>,
    pub identity_ids: Vec<String>,
    pub identity_email: String,
    pub secondary_email: String,
    pub cross_account_id: Option<String>,
    results: RefCell<Vec<Record>>,
}

impl<'x> CompCtx<'x> {
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub fn mailbox(&self, key: &str) -> &str {
        self.mailbox_ids
            .get(key)
            .unwrap_or_else(|| panic!("Seed mailbox {key} not found"))
    }

    pub fn role(&self, key: &str) -> &str {
        self.role_mailboxes
            .get(key)
            .unwrap_or_else(|| panic!("Role mailbox {key} not found"))
    }

    pub fn role_opt(&self, key: &str) -> Option<&str> {
        self.role_mailboxes.get(key).map(|s| s.as_str())
    }

    pub fn email(&self, key: &str) -> &str {
        self.email_ids
            .get(key)
            .unwrap_or_else(|| panic!("Seed email {key} not found"))
    }

    pub fn blob(&self, key: &str) -> &str {
        self.blob_ids
            .get(key)
            .unwrap_or_else(|| panic!("Seed blob {key} not found"))
    }

    pub fn upload_url(&self, account_id: &str) -> String {
        self.upload_url_tmpl.replace("{accountId}", account_id)
    }

    pub fn download_url(&self, account_id: &str, blob_id: &str, type_: &str, name: &str) -> String {
        self.download_url_tmpl
            .replace("{accountId}", account_id)
            .replace("{blobId}", blob_id)
            .replace("{type}", &pct(type_))
            .replace("{name}", &pct(name))
    }

    pub fn event_source_url(&self, types: &str, closeafter: &str, ping: &str) -> String {
        self.event_source_url_tmpl
            .replace("{types}", types)
            .replace("{closeafter}", closeafter)
            .replace("{ping}", ping)
    }

    pub async fn upload(&self, account: &Account, content_type: &str, data: Vec<u8>) -> Value {
        let url = self.upload_url(account.id_string());
        let resp = account.http_post_raw(&url, content_type, data).await;
        resp.json().unwrap_or_else(|| {
            panic!(
                "Upload returned non-JSON ({}): {}",
                resp.status,
                resp.text()
            )
        })
    }

    pub async fn run<F: Future<Output = TestOutcome>>(&self, id: &'static str, fut: F) {
        let result = AssertUnwindSafe(fut).catch_unwind().await;
        let (status, detail): (&'static str, String) = match result {
            Ok(Ok(())) => ("PASS", String::new()),
            Ok(Err(Fail::Assert(m))) => ("FAIL", m),
            Ok(Err(Fail::Skip(m))) => ("SKIP", m),
            Err(panic) => ("FAIL", panic_to_string(panic)),
        };
        let marker = match status {
            "PASS" => "\u{2713}",
            "SKIP" => "\u{2298}",
            _ => "\u{2717}",
        };
        if detail.is_empty() {
            println!("  [{marker}] {status:<4} {id}");
        } else {
            let first = detail.lines().next().unwrap_or("");
            let first: String = first.chars().take(160).collect();
            println!("  [{marker}] {status:<4} {id}  ({first})");
        }
        self.results.borrow_mut().push(Record {
            id: id.to_string(),
            status,
            detail,
        });
    }

    fn summary(&self) -> usize {
        let results = self.results.borrow();
        let (mut pass, mut fail, mut skip_n) = (0u32, 0u32, 0u32);
        for r in results.iter() {
            match r.status {
                "PASS" => pass += 1,
                "FAIL" => fail += 1,
                _ => skip_n += 1,
            }
        }

        println!("\n================ JMAP Compliance Summary ================");
        println!("Ported tests run: {}", results.len());
        println!("  PASS: {pass}   FAIL: {fail}   SKIP: {skip_n}");
        println!("\nMachine-readable results (COMPLIANCE_RESULT lines):");
        for r in results.iter() {
            println!("COMPLIANCE_RESULT\t{}\t{}", r.status, r.id);
        }
        println!("\nFailure details:");
        for r in results
            .iter()
            .filter(|r| r.status == "FAIL" && !r.detail.is_empty())
        {
            println!(
                "COMPLIANCE_DETAIL\t{}\t{}",
                r.id,
                r.detail.replace('\n', " ")
            );
        }
        println!("========================================================\n");
        fail as usize
    }
}

fn panic_to_string(e: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = e.downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = e.downcast_ref::<String>() {
        s.clone()
    } else {
        "panic (non-string payload)".to_string()
    }
}

fn pct(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

pub async fn test(test: &TestServer) {
    println!("Running JMAP compliance tests (port of jmap-test-suite)...");

    // Suppress panic backtraces during the run; failing tests panic by design.
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));

    let primary = test.account("jdoe@example.com");
    let secondary = test.account("jane.smith@example.com");

    let cross_account_id = setup_cross_account(test, primary).await;

    let ctx = build_ctx(primary, secondary, cross_account_id).await;

    test.wait_for_tasks().await;

    core::run(&ctx).await;
    identity::run(&ctx).await;
    mailbox::run(&ctx).await;
    thread::run(&ctx).await;
    binary::run(&ctx).await;
    search_snippet::run(&ctx).await;
    vacation::run(&ctx).await;
    submission::run(&ctx).await;
    push::run(test, &ctx).await;
    email::run(&ctx).await;

    let failed = ctx.summary();

    std::panic::set_hook(prev_hook);

    teardown(&ctx).await;

    if failed > 0 {
        panic!(
            "{failed} JMAP compliance test(s) failed (see COMPLIANCE_RESULT/COMPLIANCE_DETAIL above)"
        );
    }
}

async fn setup_cross_account(test: &TestServer, primary: &Account) -> Option<String> {
    let admin = test.account("admin");
    let group = test.account("sales@example.com");
    let group_id = group.id_string().to_string();

    let mut member_groups = serde_json::Map::new();
    member_groups.insert(group_id.clone(), Value::Bool(true));
    admin
        .registry_update(
            ObjectType::Account,
            [(
                primary.id(),
                json!({ Property::MemberGroupIds: member_groups }),
            )],
        )
        .await;
    admin.registry_create_object(Action::InvalidateCaches).await;

    let mb = primary
        .jmap_method_call(
            "Mailbox/get",
            json!({ "accountId": group_id, "ids": null, "properties": ["id", "role"] }),
        )
        .await;
    let has_inbox =
        mb.0.pointer("/methodResponses/0/1/list")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().any(|m| m["role"] == "inbox"))
            .unwrap_or(false);
    if !has_inbox {
        primary
            .jmap_method_call(
                "Mailbox/set",
                json!({
                    "accountId": group_id,
                    "create": { "inbox": { "name": "Inbox", "role": "inbox" } }
                }),
            )
            .await;
    }

    Some(group_id)
}

async fn build_ctx<'x>(
    primary: &'x Account,
    secondary: &'x Account,
    cross_account_id: Option<String>,
) -> CompCtx<'x> {
    let session = primary.jmap_session_object().await.into_inner();
    let account_id = primary.id_string().to_string();
    let secondary_account_id = secondary.id_string().to_string();

    let upload_url_tmpl = session
        .pointer("/uploadUrl")
        .and_then(|v| v.as_str())
        .unwrap_or("https://127.0.0.1:8899/jmap/upload/{accountId}/")
        .to_string();
    let download_url_tmpl = session
        .pointer("/downloadUrl")
        .and_then(|v| v.as_str())
        .unwrap_or("https://127.0.0.1:8899/jmap/download/{accountId}/{blobId}/{type}/{name}")
        .to_string();
    let event_source_url_tmpl = session
        .pointer("/eventSourceUrl")
        .and_then(|v| v.as_str())
        .unwrap_or(
            "https://127.0.0.1:8899/jmap/eventsource/?types={types}&closeafter={closeafter}&ping={ping}",
        )
        .to_string();

    let mut ctx = CompCtx {
        primary,
        secondary,
        account_id,
        secondary_account_id,
        session,
        upload_url_tmpl,
        download_url_tmpl,
        event_source_url_tmpl,
        mailbox_ids: HashMap::new(),
        email_ids: HashMap::new(),
        blob_ids: HashMap::new(),
        role_mailboxes: HashMap::new(),
        identity_ids: Vec::new(),
        identity_email: String::new(),
        secondary_email: String::new(),
        cross_account_id,
        results: RefCell::new(Vec::new()),
    };

    discover_roles(&mut ctx).await;
    seed_mailboxes(&mut ctx).await;
    seed_blobs(&mut ctx).await;
    seed_emails(&mut ctx).await;
    discover_identities(&mut ctx).await;

    println!(
        "Seeded: {} mailboxes, {} emails, {} blobs, {} identities (inbox role: {})",
        ctx.mailbox_ids.len(),
        ctx.email_ids.len(),
        ctx.blob_ids.len(),
        ctx.identity_ids.len(),
        ctx.role_mailboxes.contains_key("inbox"),
    );

    ctx
}

async fn discover_roles(ctx: &mut CompCtx<'_>) {
    let resp = ctx
        .primary
        .jmap_get("Mailbox", ["id", "name", "role"], Vec::<String>::new())
        .await;
    if let Some(list) = resp
        .0
        .pointer("/methodResponses/0/1/list")
        .and_then(|v| v.as_array())
    {
        for mb in list {
            if let (Some(id), Some(role)) = (
                mb.pointer("/id").and_then(|v| v.as_str()),
                mb.pointer("/role").and_then(|v| v.as_str()),
            ) {
                ctx.role_mailboxes.insert(role.to_string(), id.to_string());
            }
        }
    }
}

async fn seed_mailboxes(ctx: &mut CompCtx<'_>) {
    let resp = ctx
        .primary
        .jmap_create(
            "Mailbox",
            [
                json!({ "name": "Test Folder A", "parentId": null }),
                json!({ "name": "Test Folder B", "parentId": null }),
            ],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let folder_a = resp.created(0).id().to_string();
    let folder_b = resp.created(1).id().to_string();
    ctx.mailbox_ids.insert("folderA".into(), folder_a.clone());
    ctx.mailbox_ids.insert("folderB".into(), folder_b.clone());

    let resp = ctx
        .primary
        .jmap_create(
            "Mailbox",
            [
                json!({ "name": "Child 1", "parentId": folder_a }),
                json!({ "name": "Child 2", "parentId": folder_a }),
            ],
            Vec::<(String, Value)>::new(),
        )
        .await;
    ctx.mailbox_ids
        .insert("child1".into(), resp.created(0).id().to_string());
    ctx.mailbox_ids
        .insert("child2".into(), resp.created(1).id().to_string());
}

async fn seed_blobs(ctx: &mut CompCtx<'_>) {
    let mut pdf = vec![
        0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x34, 0x0a, 0x25, 0xe2, 0xe3, 0xcf, 0xd3, 0x0a,
    ];
    pdf.extend(std::iter::repeat_n(0x20, 100));
    let pdf_resp = ctx.upload(ctx.primary, "application/pdf", pdf).await;
    ctx.blob_ids
        .insert("pdf".into(), pdf_resp.blob_id().to_string());

    let jpeg = vec![
        0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00,
        0x01, 0x00, 0x01, 0x00, 0x00, 0xff, 0xd9,
    ];
    let jpeg_resp = ctx.upload(ctx.primary, "image/jpeg", jpeg).await;
    ctx.blob_ids
        .insert("jpeg".into(), jpeg_resp.blob_id().to_string());
}

struct SeedEmail {
    key: &'static str,
    rfc5322: String,
    mailbox_ids: Vec<String>,
    keywords: Vec<&'static str>,
    received_at: String,
}

async fn seed_emails(ctx: &mut CompCtx<'_>) {
    let now = Utc::now();
    let days_ago = |d: i64| (now - ChronoDuration::days(d)).to_rfc3339();
    let hours_ago = |h: i64| (now - ChronoDuration::hours(h)).to_rfc3339();
    let date_days_ago = |d: i64| (now - ChronoDuration::days(d)).to_rfc2822();
    let date_hours_ago = |h: i64| (now - ChronoDuration::hours(h)).to_rfc2822();

    let inbox = ctx.role("inbox").to_string();
    let drafts = ctx.role_opt("drafts").unwrap_or(&inbox).to_string();
    let folder_a = ctx.mailbox("folderA").to_string();
    let folder_b = ctx.mailbox("folderB").to_string();
    let child1 = ctx.mailbox("child1").to_string();

    let emails: Vec<SeedEmail> = vec![
        SeedEmail {
            key: "plain-simple",
            rfc5322: build_message(MsgOpts {
                from: "Alice Sender <alice@example.com>",
                to: "testuser@example.com",
                subject: "Meeting tomorrow morning",
                date: &date_days_ago(10),
                message_id: "<plain-simple-001@test>",
                body: "Let's meet tomorrow at 9am in the conference room.",
                ..Default::default()
            }),
            mailbox_ids: vec![inbox.clone()],
            keywords: vec!["$seen"],
            received_at: days_ago(10),
        },
        SeedEmail {
            key: "html-attachment",
            rfc5322: build_multipart_mixed(
                "Bob Jones <bob@example.org>",
                "testuser@example.com",
                Some("charlie@example.net"),
                "Q3 Financial Report",
                &date_days_ago(9),
                "<html-attach-001@test>",
                "<html><body><h1>Q3 Report</h1><p>Please find the report attached.</p></body></html>",
                "report.pdf",
                "application/pdf",
            ),
            mailbox_ids: vec![inbox.clone()],
            keywords: vec!["$seen", "$flagged"],
            received_at: days_ago(9),
        },
        SeedEmail {
            key: "thread-starter",
            rfc5322: build_message(MsgOpts {
                from: "testuser@example.com",
                to: "alice@example.com",
                subject: "Project Alpha Discussion",
                date: &date_days_ago(8),
                message_id: "<thread-alpha-001@test>",
                body: "I'd like to discuss the Project Alpha timeline.",
                ..Default::default()
            }),
            mailbox_ids: vec![folder_a.clone()],
            keywords: vec!["$seen"],
            received_at: days_ago(8),
        },
        SeedEmail {
            key: "thread-reply-1",
            rfc5322: build_message(MsgOpts {
                from: "Alice Sender <alice@example.com>",
                to: "testuser@example.com",
                subject: "Re: Project Alpha Discussion",
                date: &date_days_ago(7),
                message_id: "<thread-alpha-002@test>",
                in_reply_to: "<thread-alpha-001@test>",
                references: "<thread-alpha-001@test>",
                body: "Sure, let's discuss. How about Thursday?",
                ..Default::default()
            }),
            mailbox_ids: vec![inbox.clone()],
            keywords: vec![],
            received_at: days_ago(7),
        },
        SeedEmail {
            key: "thread-reply-2",
            rfc5322: build_message(MsgOpts {
                from: "Bob Jones <bob@example.org>",
                to: "testuser@example.com, alice@example.com",
                subject: "Re: Project Alpha Discussion",
                date: &date_days_ago(6),
                message_id: "<thread-alpha-003@test>",
                in_reply_to: "<thread-alpha-002@test>",
                references: "<thread-alpha-001@test> <thread-alpha-002@test>",
                body: "Thursday works for me. I'll bring the xylophone presentation materials.",
                ..Default::default()
            }),
            mailbox_ids: vec![inbox.clone()],
            keywords: vec!["$answered"],
            received_at: days_ago(6),
        },
        SeedEmail {
            key: "multi-mailbox",
            rfc5322: build_message(MsgOpts {
                from: "David Cross <david@example.com>",
                to: "testuser@example.com",
                subject: "Cross-filed document",
                date: &date_days_ago(5),
                message_id: "<multi-mb-001@test>",
                body: "This document should appear in multiple folders.",
                ..Default::default()
            }),
            mailbox_ids: vec![inbox.clone(), folder_a.clone()],
            keywords: vec!["$seen"],
            received_at: days_ago(5),
        },
        SeedEmail {
            key: "large-email",
            rfc5322: build_message(MsgOpts {
                from: "Eve Large <eve@example.com>",
                to: "testuser@example.com",
                subject: "Detailed analysis with data",
                date: &date_days_ago(4),
                message_id: "<large-001@test>",
                body: &format!(
                    "Start of analysis. {}End of analysis.",
                    "This is a detailed paragraph of analysis text that covers various topics. "
                        .repeat(700)
                ),
                ..Default::default()
            }),
            mailbox_ids: vec![folder_b.clone()],
            keywords: vec![],
            received_at: days_ago(4),
        },
        SeedEmail {
            key: "html-only",
            rfc5322: build_multipart_alternative(
                "Frank Newsletter <frank@example.com>",
                "testuser@example.com",
                "Newsletter: Weekly Digest",
                &date_days_ago(3),
                "<html-only-001@test>",
                "Weekly Digest - plain text version",
                "<html><body><h1>Weekly Digest</h1><p>Here is your <b>weekly digest</b> of news.</p><img src=\"cid:image1\"/></body></html>",
            ),
            mailbox_ids: vec![inbox.clone()],
            keywords: vec!["$seen"],
            received_at: days_ago(3),
        },
        SeedEmail {
            key: "no-subject",
            rfc5322: build_message(MsgOpts {
                from: "Grace Minimal <grace@example.com>",
                to: "testuser@example.com",
                subject: "",
                date: &date_days_ago(2),
                message_id: "<no-subj-001@test>",
                body: "This message has no subject.",
                ..Default::default()
            }),
            mailbox_ids: vec![inbox.clone()],
            keywords: vec!["$seen"],
            received_at: days_ago(2),
        },
        SeedEmail {
            key: "custom-keywords",
            rfc5322: build_message(MsgOpts {
                from: "Henry Tags <henry@example.com>",
                to: "testuser@example.com",
                subject: "Tagged message",
                date: &date_days_ago(1),
                message_id: "<custom-kw-001@test>",
                body: "This message has custom keywords applied.",
                ..Default::default()
            }),
            mailbox_ids: vec![inbox.clone()],
            keywords: vec!["$seen", "$forwarded", "custom_label"],
            received_at: days_ago(1),
        },
        SeedEmail {
            key: "very-old",
            rfc5322: build_message(MsgOpts {
                from: "Iris Archive <iris@example.com>",
                to: "testuser@example.com",
                subject: "Archived correspondence",
                date: &date_days_ago(30),
                message_id: "<old-001@test>",
                body: "This is an old archived email from a month ago.",
                ..Default::default()
            }),
            mailbox_ids: vec![folder_a.clone()],
            keywords: vec!["$seen"],
            received_at: days_ago(30),
        },
        SeedEmail {
            key: "bcc-email",
            rfc5322: build_message(MsgOpts {
                from: "testuser@example.com",
                to: "jack@example.com",
                bcc: "secret@example.com",
                subject: "Confidential note",
                date: &date_days_ago(2),
                message_id: "<bcc-001@test>",
                body: "This is a confidential message with a BCC recipient.",
                ..Default::default()
            }),
            mailbox_ids: vec![folder_a.clone()],
            keywords: vec!["$seen", "$draft"],
            received_at: days_ago(2),
        },
        SeedEmail {
            key: "special-headers",
            rfc5322: build_message(MsgOpts {
                from: "List Admin <list-admin@example.com>",
                to: "testuser@example.com",
                subject: "Mailing list post",
                date: &date_days_ago(1),
                message_id: "<list-001@test>",
                body: "This is a post from a mailing list.",
                extra_headers: vec![
                    "List-Post: <mailto:list@example.com>",
                    "List-Unsubscribe: <https://example.com/unsub>",
                    "X-Custom-Header: custom-value-12345",
                ],
                ..Default::default()
            }),
            mailbox_ids: vec![inbox.clone()],
            keywords: vec!["$seen"],
            received_at: days_ago(1),
        },
        SeedEmail {
            key: "multipart-related",
            rfc5322: build_multipart_related(
                "Kate Images <kate@example.com>",
                "testuser@example.com",
                "Image embedded email",
                &date_hours_ago(12),
                "<related-001@test>",
                "<html><body><p>See the image below:</p><img src=\"cid:image001@test\"/></body></html>",
                "image001@test",
            ),
            mailbox_ids: vec![inbox.clone()],
            keywords: vec!["$seen"],
            received_at: hours_ago(12),
        },
        SeedEmail {
            key: "intl-sender",
            rfc5322: build_message(MsgOpts {
                from: "=?UTF-8?B?6YeR5Z+O5q2m?= <kaneshiro@example.com>",
                to: "testuser@example.com",
                subject: "=?UTF-8?B?44GT44KT44Gr44Gh44Gv?=",
                date: &date_hours_ago(6),
                message_id: "<intl-001@test>",
                body: "This message has an internationalized sender name and subject.",
                ..Default::default()
            }),
            mailbox_ids: vec![inbox.clone()],
            keywords: vec![],
            received_at: hours_ago(6),
        },
        SeedEmail {
            key: "sort-test-1",
            rfc5322: build_message(MsgOpts {
                from: "Zara First <zara@example.com>",
                to: "testuser@example.com",
                subject: "Alpha sort test",
                date: &date_days_ago(5),
                message_id: "<sort-001@test>",
                body: &"A".repeat(100),
                ..Default::default()
            }),
            mailbox_ids: vec![folder_b.clone()],
            keywords: vec!["$seen"],
            received_at: days_ago(3),
        },
        SeedEmail {
            key: "sort-test-2",
            rfc5322: build_message(MsgOpts {
                from: "Amy Second <amy@example.com>",
                to: "testuser@example.com",
                subject: "Beta sort test",
                date: &date_days_ago(3),
                message_id: "<sort-002@test>",
                body: &"B".repeat(500),
                ..Default::default()
            }),
            mailbox_ids: vec![folder_b.clone()],
            keywords: vec!["$seen", "$flagged"],
            received_at: days_ago(2),
        },
        SeedEmail {
            key: "sort-test-3",
            rfc5322: build_message(MsgOpts {
                from: "Mike Third <mike@example.com>",
                to: "testuser@example.com",
                subject: "Gamma sort test",
                date: &date_days_ago(1),
                message_id: "<sort-003@test>",
                body: &"C".repeat(50),
                ..Default::default()
            }),
            mailbox_ids: vec![folder_b.clone()],
            keywords: vec![],
            received_at: days_ago(1),
        },
        SeedEmail {
            key: "draft-for-submission",
            rfc5322: build_message(MsgOpts {
                from: "jdoe@example.com",
                to: "jane.smith@example.com",
                subject: "Test submission email",
                date: &date_hours_ago(1),
                message_id: "<submission-001@test>",
                body: "This email will be used for submission testing.",
                ..Default::default()
            }),
            mailbox_ids: vec![drafts.clone()],
            keywords: vec!["$seen", "$draft"],
            received_at: hours_ago(1),
        },
        SeedEmail {
            key: "child-mailbox-email",
            rfc5322: build_message(MsgOpts {
                from: "Nancy Nested <nancy@example.com>",
                to: "testuser@example.com",
                subject: "In nested folder",
                date: &date_days_ago(5),
                message_id: "<child-001@test>",
                body: "This email lives in a nested child mailbox.",
                ..Default::default()
            }),
            mailbox_ids: vec![child1.clone()],
            keywords: vec!["$seen"],
            received_at: days_ago(5),
        },
        SeedEmail {
            key: "korean-euckr",
            rfc5322: {
                let body_b64 = general_purpose::STANDARD.encode([
                    0xc5, 0xd7, 0xbd, 0xba, 0xc6, 0xae, 0x20, 0xc0, 0xcc, 0xb8, 0xde, 0xc0, 0xcf,
                    0xc0, 0xd4, 0xb4, 0xcf, 0xb4, 0xd9,
                ]);
                [
                    "From: =?EUC-KR?B?seS/tbjR?= <korean-sender@example.com>",
                    "To: testuser@example.com",
                    "Subject: =?EUC-KR?B?sNa0z7TZx9Cw+A==?=",
                    &format!("Date: {}", date_hours_ago(5)),
                    "Message-ID: <korean-001@test>",
                    "MIME-Version: 1.0",
                    "Content-Type: text/plain; charset=EUC-KR",
                    "Content-Transfer-Encoding: base64",
                    "",
                    &body_b64,
                ]
                .join("\r\n")
            },
            mailbox_ids: vec![inbox.clone()],
            keywords: vec!["$seen"],
            received_at: hours_ago(5),
        },
        SeedEmail {
            key: "invalid-ascii",
            rfc5322: [
                "From: broken@example.com",
                "To: testuser@example.com",
                "Subject: Malformed email test",
                &format!("Date: {}", date_hours_ago(4)),
                "Message-ID: <invalid-001@test>",
                "MIME-Version: 1.0",
                "Content-Type: text/plain; charset=us-ascii",
                "X-Broken-Header: value with \u{01}\u{02} control chars",
                "",
                "This email has some issues.\r\n",
                &format!(
                    "It has a line that is way too long: {}\r\n",
                    "x".repeat(1000)
                ),
                "And some 8-bit chars in ASCII: caf\u{e9} na\u{ef}ve r\u{e9}sum\u{e9}\r\n",
                "End of message.",
            ]
            .join("\r\n"),
            mailbox_ids: vec![inbox.clone()],
            keywords: vec!["$seen"],
            received_at: hours_ago(4),
        },
    ];

    for batch in emails.chunks(5) {
        import_batch(ctx, batch).await;
    }
}

async fn import_batch(ctx: &mut CompCtx<'_>, batch: &[SeedEmail]) {
    let mut blob_ids: HashMap<&str, String> = HashMap::new();
    for email in batch {
        let resp = ctx
            .upload(
                ctx.primary,
                "message/rfc5322",
                email.rfc5322.clone().into_bytes(),
            )
            .await;
        blob_ids.insert(email.key, resp.blob_id().to_string());
    }

    let mut import_map = serde_json::Map::new();
    for email in batch {
        let keywords: serde_json::Map<String, Value> = email
            .keywords
            .iter()
            .map(|k| (k.to_string(), Value::Bool(true)))
            .collect();
        let mailboxes: serde_json::Map<String, Value> = email
            .mailbox_ids
            .iter()
            .map(|m| (m.clone(), Value::Bool(true)))
            .collect();
        import_map.insert(
            email.key.to_string(),
            json!({
                "blobId": blob_ids[email.key],
                "mailboxIds": mailboxes,
                "keywords": keywords,
                "receivedAt": email.received_at,
            }),
        );
    }

    let resp = ctx
        .primary
        .jmap_method_call(
            "Email/import",
            json!({ "accountId": ctx.account_id, "emails": import_map }),
        )
        .await;

    for email in batch {
        if let Some(id) = resp
            .0
            .pointer(&format!("/methodResponses/0/1/created/{}/id", email.key))
            .and_then(|v| v.as_str())
        {
            ctx.email_ids.insert(email.key.to_string(), id.to_string());
        } else if let Some(err) = resp
            .0
            .pointer(&format!("/methodResponses/0/1/notCreated/{}", email.key))
        {
            println!("  Warning: failed to import '{}': {}", email.key, err);
        }
    }
}

async fn discover_identities(ctx: &mut CompCtx<'_>) {
    let resp = ctx
        .primary
        .jmap_method_call(
            "Identity/get",
            json!({ "accountId": ctx.account_id, "ids": null }),
        )
        .await;
    if let Some(list) = resp
        .0
        .pointer("/methodResponses/0/1/list")
        .and_then(|v| v.as_array())
    {
        for ident in list {
            if let Some(id) = ident.pointer("/id").and_then(|v| v.as_str()) {
                ctx.identity_ids.push(id.to_string());
            }
        }
        if let Some(email) = list
            .first()
            .and_then(|i| i.pointer("/email"))
            .and_then(|v| v.as_str())
        {
            ctx.identity_email = email.to_string();
        }
    }

    let resp = ctx
        .secondary
        .jmap_method_call(
            "Identity/get",
            json!({ "accountId": ctx.secondary_account_id, "ids": null }),
        )
        .await;
    if let Some(email) = resp
        .0
        .pointer("/methodResponses/0/1/list/0/email")
        .and_then(|v| v.as_str())
    {
        ctx.secondary_email = email.to_string();
    }
}

async fn teardown(ctx: &CompCtx<'_>) {
    for account in [ctx.primary, ctx.secondary] {
        let emails = account
            .jmap_query(
                "Email",
                Vec::<(String, Value)>::new(),
                Vec::<String>::new(),
                [("limit", Value::from(10000))],
            )
            .await;
        let ids: Vec<String> = emails
            .0
            .pointer("/methodResponses/0/1/ids")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        if !ids.is_empty() {
            account
                .jmap_destroy("Email", ids, Vec::<(String, Value)>::new())
                .await;
        }
        account.jmap_client().await.destroy_all_mailboxes().await;
    }
}

// --- RFC 5322 message builders (ports of seed-data.ts) ---

#[derive(Default)]
struct MsgOpts<'a> {
    from: &'a str,
    to: &'a str,
    cc: &'a str,
    bcc: &'a str,
    subject: &'a str,
    date: &'a str,
    message_id: &'a str,
    in_reply_to: &'a str,
    references: &'a str,
    body: &'a str,
    extra_headers: Vec<&'a str>,
}

fn build_message(o: MsgOpts) -> String {
    let mut lines = vec![format!("From: {}", o.from), format!("To: {}", o.to)];
    if !o.cc.is_empty() {
        lines.push(format!("Cc: {}", o.cc));
    }
    if !o.bcc.is_empty() {
        lines.push(format!("Bcc: {}", o.bcc));
    }
    lines.push(format!("Subject: {}", o.subject));
    lines.push(format!("Date: {}", o.date));
    lines.push(format!("Message-ID: {}", o.message_id));
    if !o.in_reply_to.is_empty() {
        lines.push(format!("In-Reply-To: {}", o.in_reply_to));
    }
    if !o.references.is_empty() {
        lines.push(format!("References: {}", o.references));
    }
    lines.push("MIME-Version: 1.0".into());
    lines.push("Content-Type: text/plain; charset=UTF-8".into());
    lines.push("Content-Transfer-Encoding: 7bit".into());
    for h in &o.extra_headers {
        lines.push(h.to_string());
    }
    lines.push(String::new());
    lines.push(o.body.to_string());
    lines.join("\r\n")
}

#[allow(clippy::too_many_arguments)]
fn build_multipart_mixed(
    from: &str,
    to: &str,
    cc: Option<&str>,
    subject: &str,
    date: &str,
    message_id: &str,
    html_body: &str,
    attachment_name: &str,
    attachment_type: &str,
) -> String {
    let boundary = "----=_Part_001_boundary";
    let mut lines = vec![format!("From: {from}"), format!("To: {to}")];
    if let Some(cc) = cc {
        lines.push(format!("Cc: {cc}"));
    }
    lines.push(format!("Subject: {subject}"));
    lines.push(format!("Date: {date}"));
    lines.push(format!("Message-ID: {message_id}"));
    lines.push("MIME-Version: 1.0".into());
    lines.push(format!(
        "Content-Type: multipart/mixed; boundary=\"{boundary}\""
    ));
    lines.push(String::new());
    lines.push(format!("--{boundary}"));
    lines.push("Content-Type: text/html; charset=UTF-8".into());
    lines.push("Content-Transfer-Encoding: 7bit".into());
    lines.push(String::new());
    lines.push(html_body.to_string());
    lines.push(format!("--{boundary}"));
    lines.push(format!(
        "Content-Type: {attachment_type}; name=\"{attachment_name}\""
    ));
    lines.push(format!(
        "Content-Disposition: attachment; filename=\"{attachment_name}\""
    ));
    lines.push("Content-Transfer-Encoding: base64".into());
    lines.push(String::new());
    lines.push(
        general_purpose::STANDARD
            .encode("%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"),
    );
    lines.push(format!("--{boundary}--"));
    lines.join("\r\n")
}

fn build_multipart_alternative(
    from: &str,
    to: &str,
    subject: &str,
    date: &str,
    message_id: &str,
    text_body: &str,
    html_body: &str,
) -> String {
    let boundary = "----=_Alt_001_boundary";
    vec![
        format!("From: {from}"),
        format!("To: {to}"),
        format!("Subject: {subject}"),
        format!("Date: {date}"),
        format!("Message-ID: {message_id}"),
        "MIME-Version: 1.0".into(),
        format!("Content-Type: multipart/alternative; boundary=\"{boundary}\""),
        String::new(),
        format!("--{boundary}"),
        "Content-Type: text/plain; charset=UTF-8".into(),
        "Content-Transfer-Encoding: 7bit".into(),
        String::new(),
        text_body.to_string(),
        format!("--{boundary}"),
        "Content-Type: text/html; charset=UTF-8".into(),
        "Content-Transfer-Encoding: 7bit".into(),
        String::new(),
        html_body.to_string(),
        format!("--{boundary}--"),
    ]
    .join("\r\n")
}

fn build_multipart_related(
    from: &str,
    to: &str,
    subject: &str,
    date: &str,
    message_id: &str,
    html_body: &str,
    inline_image_cid: &str,
) -> String {
    let boundary = "----=_Rel_001_boundary";
    let jpeg = general_purpose::STANDARD.encode([
        0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00,
        0x01, 0x00, 0x01, 0x00, 0x00, 0xff, 0xd9,
    ]);
    vec![
        format!("From: {from}"),
        format!("To: {to}"),
        format!("Subject: {subject}"),
        format!("Date: {date}"),
        format!("Message-ID: {message_id}"),
        "MIME-Version: 1.0".into(),
        format!("Content-Type: multipart/related; boundary=\"{boundary}\""),
        String::new(),
        format!("--{boundary}"),
        "Content-Type: text/html; charset=UTF-8".into(),
        "Content-Transfer-Encoding: 7bit".into(),
        String::new(),
        html_body.to_string(),
        format!("--{boundary}"),
        "Content-Type: image/jpeg".into(),
        format!("Content-ID: <{inline_image_cid}>"),
        "Content-Disposition: inline".into(),
        "Content-Transfer-Encoding: base64".into(),
        String::new(),
        jpeg,
        format!("--{boundary}--"),
    ]
    .join("\r\n")
}
