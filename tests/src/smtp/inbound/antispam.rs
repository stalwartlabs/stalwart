/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{
    dns::DnsCache,
    http_server::{HttpMessage, spawn_mock_http_server},
    server::TestServerBuilder,
};
use ahash::AHashSet;
use common::{
    Server,
    auth::{AccountCache, AccountInfo},
    config::mailstore::spamfilter::SpamFilterAction,
    enterprise::llm::{
        ChatCompletionChoice, ChatCompletionRequest, ChatCompletionResponse, Message,
    },
};
use http_proto::{JsonResponse, ToHttpResponse};
use hyper::Method;
use mail_auth::{
    ArcOutput, DkimOutput, DkimResult, DmarcResult, DnssecStatus, IprevOutput, IprevResult, MX,
    SpfOutput, SpfResult, dkim::Signature, dmarc::Policy,
};
use mail_parser::MessageParser;
use registry::{
    schema::{
        enums::{AiModelType, TaskSpamFilterMaintenanceType},
        prelude::{ObjectType, Property},
        structs::{
            self, AiModel, MemoryLookupKey, SpamLlm, SpamLlmProperties, SpamSettings, Task,
            TaskSpamFilterMaintenance, TaskStatus,
        },
    },
    types::{float::Float, map::Map},
};
use serde_json::json;
use smtp::core::SessionAddress;
use smtp_proto::{MAIL_BODY_8BITMIME, MAIL_SMTPUTF8};
use spam_filter::{
    SpamFilterInput,
    analysis::{
        classifier::SpamFilterAnalyzeClassify, date::SpamFilterAnalyzeDate,
        dmarc::SpamFilterAnalyzeDmarc, domain::SpamFilterAnalyzeDomain,
        ehlo::SpamFilterAnalyzeEhlo, from::SpamFilterAnalyzeFrom,
        headers::SpamFilterAnalyzeHeaders, html::SpamFilterAnalyzeHtml, init::SpamFilterInit,
        ip::SpamFilterAnalyzeIp, llm::SpamFilterAnalyzeLlm, messageid::SpamFilterAnalyzeMid,
        mime::SpamFilterAnalyzeMime, pyzor::SpamFilterAnalyzePyzor,
        received::SpamFilterAnalyzeReceived, recipient::SpamFilterAnalyzeRecipient,
        replyto::SpamFilterAnalyzeReplyTo, rules::SpamFilterAnalyzeRules,
        score::SpamFilterAnalyzeScore, subject::SpamFilterAnalyzeSubject,
        url::SpamFilterAnalyzeUrl,
    },
    modules::{
        classifier::{SpamClassifier, Token},
        html::{HtmlToken, html_to_tokens},
    },
};
use std::{
    fs,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

#[tokio::test(flavor = "multi_thread")]
async fn antispam() {
    let mut test = TestServerBuilder::new("smtp_antispam_test")
        .await
        .with_http_listener(19048)
        .await
        .build()
        .await;

    let admin = test.account("admin");
    admin
        .registry_create_object(SpamSettings {
            score_spam: Float::new(5.0),
            spam_filter_rules_url: std::env::var("SPAM_RULES_URL")
                .unwrap_or_else(|_| {
                    "file:///Users/me/code/spam-filter/spam-filter-rules.json.gz".to_string()
                })
                .into(),
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(structs::SpamClassifier {
            min_ham_samples: 10,
            min_spam_samples: 10,
            ..Default::default()
        })
        .await;
    let model_id = admin
        .registry_create_object(AiModel {
            model_type: AiModelType::Chat,
            allow_invalid_certs: true,
            model: "gpt-dummy".to_string(),
            name: "dummy".to_string(),
            url: "https://127.0.0.1:9090/v1/chat/completions".to_string(),
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(SpamLlm::Enable(SpamLlmProperties {
            categories: Map::new(vec![
                "Unsolicited".to_string(),
                "Commercial".to_string(),
                "Harmful".to_string(),
                "Legitimate".to_string(),
            ]),
            confidence: Map::new(vec![
                "High".to_string(),
                "Medium".to_string(),
                "Low".to_string(),
            ]),
            model_id,
            prompt: "You are an AI assistant specialized in analyzing email content to detect spam"
                .to_string(),
            response_pos_category: 0,
            response_pos_confidence: 1.into(),
            response_pos_explanation: 2.into(),
            separator: ",".to_string(),
            ..Default::default()
        }))
        .await;
    admin
        .registry_create_object(MemoryLookupKey {
            is_glob_pattern: true,
            key: "spamtrap@*".into(),
            namespace: "spam-traps".into(),
        })
        .await;
    admin
        .registry_create_object(MemoryLookupKey {
            is_glob_pattern: true,
            key: "redirect.*".into(),
            namespace: "url-redirectors".into(),
        })
        .await;
    admin.mta_allow_relaying().await;
    admin.mta_no_auth().await;
    admin.mta_allow_non_fqdn().await;
    admin.reload_settings().await;

    // Fetch rules
    admin
        .registry_create_object(Task::SpamFilterMaintenance(TaskSpamFilterMaintenance {
            maintenance_type: TaskSpamFilterMaintenanceType::UpdateRules,
            status: TaskStatus::now(),
        }))
        .await;
    test.wait_for_tasks().await;
    admin.reload_settings().await;
    admin.reload_lookup_stores().await;
    test.reload_core();
    let admin = test.account("admin");

    // Add mock DNS entries
    for (domain, ip) in [
        ("bank.com", "127.0.0.1"),
        ("apple.com", "127.0.0.1"),
        ("youtube.com", "127.0.0.1"),
        ("twitter.com", "127.0.0.3"),
        ("dkimtrusted.org.dwl.dnswl.org", "127.0.0.3"),
        ("sh-malware.com.dbl.spamhaus.org", "127.0.1.5"),
        ("surbl-abuse.com.multi.surbl.org", "127.0.0.64"),
        ("uribl-grey.com.multi.uribl.com", "127.0.0.4"),
        ("sem-uribl.com.uribl.spameatingmonkey.net", "127.0.0.2"),
        ("sem-fresh15.com.fresh15.spameatingmonkey.net", "127.0.0.2"),
        (
            "b4a64d60f67529b0b18df66ea2f292e09e43c975.ebl.msbl.org",
            "127.0.0.2",
        ),
        (
            "a95bd658068a8315dc1864d6bb79632f47692621.ebl.msbl.org",
            "127.0.1.3",
        ),
        (
            "ba76e47680ba70a0cbff8d6c92139683.hashbl.surbl.org",
            "127.0.0.16",
        ),
        (
            "0ac5b387a1c6d8461a78bbf7b172a2a1.hashbl.surbl.org",
            "127.0.0.64",
        ),
        (
            "ef6f530a68b77d782983e8712ff31fe5.hashbl.surbl.org",
            "127.0.0.8",
        ),
    ] {
        test.server.ipv4_add(
            domain,
            vec![ip.parse().unwrap()],
            Instant::now() + Duration::from_secs(100),
        );
        test.server.dnsbl_add(
            domain,
            vec![ip.parse().unwrap()],
            Instant::now() + Duration::from_secs(100),
        );
    }
    for mx in [
        "domain.org",
        "domain.co.uk",
        "gmail.com",
        "custom.disposable.org",
    ] {
        test.server.mx_add(
            mx,
            vec![MX {
                exchanges: vec!["127.0.0.1".into()].into_boxed_slice(),
                preference: 10,
            }],
            DnssecStatus::Secure,
            Instant::now() + Duration::from_secs(100),
        );
    }

    // Spawn mock OpenAI server
    let _tx = spawn_mock_http_server(
        &test,
        Arc::new(|req: HttpMessage| {
            assert_eq!(req.uri.path(), "/v1/chat/completions");
            assert_eq!(req.method, Method::POST);
            let req = serde_json::from_slice::<ChatCompletionRequest>(req.body.as_ref().unwrap())
                .unwrap();
            assert_eq!(req.model, "gpt-dummy");
            let message = &req.messages[0].content;
            assert!(message.contains("You are an AI assistant specialized in analyzing email"));

            JsonResponse::new(&ChatCompletionResponse {
                created: 0,
                object: String::new(),
                id: String::new(),
                model: req.model,
                choices: vec![ChatCompletionChoice {
                    index: 0,
                    finish_reason: "stop".to_string(),
                    message: Message {
                        role: "assistant".to_string(),
                        content: message.split_once("Subject: ").unwrap().1.to_string(),
                    },
                }],
            })
            .into_http_response()
        }),
        9090,
    )
    .await;

    // Run tests
    let base_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("resources")
        .join("smtp")
        .join("antispam");
    let filter_test = std::env::var("TEST_NAME").ok();

    for test_name in [
        "combined",
        "ip",
        "helo",
        "received",
        "messageid",
        "date",
        "from",
        "subject",
        "replyto",
        "recipient",
        "headers",
        "url",
        "html",
        "mime",
        "bounce",
        "dmarc",
        "rbl",
        "spamtrap",
        "classifier_html",
        "classifier_features",
        "classifier",
        "pyzor",
        "llm",
    ] {
        if filter_test
            .as_ref()
            .is_some_and(|s| !s.eq_ignore_ascii_case(test_name))
        {
            continue;
        }

        println!("===== {test_name} =====");
        let contents = fs::read_to_string(base_path.join(format!("{test_name}.test"))).unwrap();

        match test_name {
            "classifier_html" => {
                html_tokens(contents);
                continue;
            }
            "classifier_features" => {
                classifier_features(&test.server, contents).await;
                continue;
            }
            "classifier" => {
                for class in ["spam", "ham"] {
                    let contents =
                        fs::read_to_string(base_path.join(format!("classifier.{class}"))).unwrap();
                    for sample in contents.split("<!-- NEXT TEST -->") {
                        let sample = sample.trim_start();
                        if sample.is_empty() {
                            continue;
                        }

                        let blob_id = test
                            .server
                            .put_jmap_blob(u32::MAX, sample.as_bytes())
                            .await
                            .unwrap();
                        admin
                            .registry_create_many(
                                ObjectType::SpamTrainingSample,
                                [json!({
                                    Property::BlobId: blob_id,
                                    Property::IsSpam: class == "spam",
                                })],
                            )
                            .await
                            .created_id(0);
                    }
                }
                admin
                    .registry_create_object(Task::SpamFilterMaintenance(
                        TaskSpamFilterMaintenance {
                            maintenance_type: TaskSpamFilterMaintenanceType::Train,
                            status: TaskStatus::now(),
                        },
                    ))
                    .await;
                test.wait_for_tasks().await;
            }
            _ => {}
        }

        let mut lines = contents.lines();
        let mut has_more = true;

        while has_more {
            let mut message = String::new();
            let mut in_params = true;

            // Build session
            let mut session = test.new_mta_session();
            let mut arc_result = None;
            let mut dkim_result = None;
            let mut dkim_signatures = vec![];
            let mut dmarc_result = None;
            let mut dmarc_policy = None;
            let mut expected_tags: AHashSet<String> = AHashSet::new();
            let mut expect_headers = String::new();
            let mut body_params = 0;
            let mut is_tls = false;

            for line in lines.by_ref() {
                if in_params {
                    if line.is_empty() {
                        in_params = false;
                        continue;
                    }
                    let (param, value) = line.split_once(' ').unwrap();
                    let value = value.trim();
                    match param {
                        "remote_ip" => {
                            session.data.remote_ip_str = value.to_string();
                            session.data.remote_ip = value.parse().unwrap();
                        }
                        "helo_domain" => {
                            session.data.helo_domain = value.to_string();
                        }
                        "authenticated_as" => {
                            session.data.authenticated_as = Some(AccountInfo {
                                account_id: u32::MAX,
                                addresses: vec![value.to_string()],
                                account: Arc::new(AccountCache {
                                    name: value.into(),
                                    ..Default::default()
                                }),
                            });
                        }
                        "spf.result" | "spf_ehlo.result" => {
                            session.data.spf_mail_from =
                                Some(SpfOutput::default().with_result(SpfResult::from_str(value)));
                        }
                        "iprev.result" => {
                            session
                                .data
                                .iprev
                                .get_or_insert(IprevOutput {
                                    result: IprevResult::None,
                                    ptr: None,
                                })
                                .result = IprevResult::from_str(value);
                        }
                        "dkim.result" => {
                            dkim_result = match DkimResult::from_str(value) {
                                DkimResult::Pass => DkimOutput::pass(),
                                DkimResult::Neutral(error) => DkimOutput::neutral(error),
                                DkimResult::Fail(error) => DkimOutput::fail(error),
                                DkimResult::PermError(error) => DkimOutput::perm_err(error),
                                DkimResult::TempError(error) => DkimOutput::temp_err(error),
                                DkimResult::None => unreachable!(),
                            }
                            .into();
                        }
                        "arc.result" => {
                            arc_result = ArcOutput::default()
                                .with_result(DkimResult::from_str(value))
                                .into();
                        }
                        "dkim.domains" => {
                            dkim_signatures = value
                                .split_ascii_whitespace()
                                .map(|s| Signature {
                                    d: s.to_lowercase(),
                                    ..Default::default()
                                })
                                .collect();
                        }
                        "envelope_from" => {
                            session.data.mail_from = Some(SessionAddress::new(value.to_string()));
                        }
                        "envelope_to" => {
                            session
                                .data
                                .rcpt_to
                                .push(SessionAddress::new(value.to_string()));
                        }
                        "iprev.ptr" => {
                            session
                                .data
                                .iprev
                                .get_or_insert(IprevOutput {
                                    result: IprevResult::None,
                                    ptr: None,
                                })
                                .ptr = Some(Arc::from(vec![value.into()]));
                        }
                        "dmarc.result" => {
                            dmarc_result = DmarcResult::from_str(value).into();
                        }
                        "dmarc.policy" => {
                            dmarc_policy = Policy::from_str(value).into();
                        }
                        "expect" => {
                            expected_tags
                                .extend(value.split_ascii_whitespace().map(|v| v.to_uppercase()));
                        }
                        "expect_header" => {
                            let value = value.trim();
                            if !value.is_empty() {
                                if !expect_headers.is_empty() {
                                    expect_headers.push(' ');
                                }
                                expect_headers.push_str(value);
                            }
                        }
                        "param.smtputf8" => {
                            body_params |= MAIL_SMTPUTF8;
                        }
                        "param.8bitmime" => {
                            body_params |= MAIL_BODY_8BITMIME;
                        }
                        "tls.version" => {
                            is_tls = true;
                        }
                        _ => panic!("Invalid parameter {param:?}"),
                    }
                } else {
                    has_more = line.trim().eq_ignore_ascii_case("<!-- NEXT TEST -->");
                    if !has_more {
                        message.push_str(line);
                        message.push_str("\r\n");
                    } else {
                        break;
                    }
                }
            }

            if message.is_empty() {
                panic!("No message found");
            }

            if body_params != 0 {
                session
                    .data
                    .mail_from
                    .get_or_insert_with(|| SessionAddress::new("".to_string()))
                    .flags = body_params;
            }

            // Build input
            let mut dkim_domains = vec![];
            if let Some(dkim_result) = dkim_result {
                if dkim_signatures.is_empty() {
                    dkim_signatures.push(Signature {
                        d: "unknown.org".to_string(),
                        ..Default::default()
                    });
                }

                for signature in &dkim_signatures {
                    dkim_domains.push(dkim_result.clone().with_signature(signature));
                }
            }
            let parsed_message = MessageParser::new().parse(&message).unwrap();

            // Combined tests
            if test_name == "combined" {
                match session
                    .spam_classify(
                        &parsed_message,
                        &dkim_domains,
                        None,
                        arc_result.as_ref(),
                        dmarc_result.as_ref(),
                        dmarc_policy.as_ref(),
                    )
                    .await
                {
                    SpamFilterAction::Allow(score) => {
                        let mut last_ch = 'x';
                        let mut result = String::with_capacity(score.headers.len());
                        for ch in score.headers.chars() {
                            if !ch.is_whitespace() {
                                if last_ch.is_whitespace() {
                                    result.push(' ');
                                }
                                result.push(ch);
                            }
                            last_ch = ch;
                        }
                        assert_eq!(result, expect_headers);
                    }
                    other => panic!("Unexpected action {other:?}"),
                }
                continue;
            }

            // Initialize filter
            let mut spam_input = session.build_spam_input(
                &parsed_message,
                &dkim_domains,
                None,
                arc_result.as_ref(),
                dmarc_result.as_ref(),
                dmarc_policy.as_ref(),
            );
            spam_input.is_tls = is_tls;
            let server = &test.server;
            let mut spam_ctx = server.spam_filter_init(spam_input);
            match test_name {
                "html" => {
                    server.spam_filter_analyze_html(&mut spam_ctx).await;
                    server.spam_filter_analyze_rules(&mut spam_ctx).await;
                }
                "subject" => {
                    server.spam_filter_analyze_headers(&mut spam_ctx).await;
                    spam_ctx.result.tags.retain(|t| t.starts_with("X_HDR_"));
                    server.spam_filter_analyze_subject(&mut spam_ctx).await;
                    server.spam_filter_analyze_rules(&mut spam_ctx).await;
                    spam_ctx.result.tags.retain(|t| !t.starts_with("X_HDR_"));
                }
                "received" => {
                    server.spam_filter_analyze_headers(&mut spam_ctx).await;
                    spam_ctx.result.tags.retain(|t| t.starts_with("X_HDR_"));
                    server.spam_filter_analyze_received(&mut spam_ctx).await;
                    server.spam_filter_analyze_rules(&mut spam_ctx).await;
                    spam_ctx.result.tags.retain(|t| !t.starts_with("X_HDR_"));
                }
                "messageid" => {
                    server.spam_filter_analyze_message_id(&mut spam_ctx).await;
                }
                "date" => {
                    server.spam_filter_analyze_date(&mut spam_ctx).await;
                }
                "from" => {
                    server.spam_filter_analyze_from(&mut spam_ctx).await;
                    server.spam_filter_analyze_domain(&mut spam_ctx).await;
                    server.spam_filter_analyze_rules(&mut spam_ctx).await;
                }
                "replyto" => {
                    server.spam_filter_analyze_reply_to(&mut spam_ctx).await;
                    server.spam_filter_analyze_domain(&mut spam_ctx).await;
                    server.spam_filter_analyze_rules(&mut spam_ctx).await;
                }
                "recipient" => {
                    server.spam_filter_analyze_headers(&mut spam_ctx).await;
                    spam_ctx.result.tags.retain(|t| t.starts_with("X_HDR_"));
                    server.spam_filter_analyze_recipient(&mut spam_ctx).await;
                    server.spam_filter_analyze_domain(&mut spam_ctx).await;
                    server.spam_filter_analyze_subject(&mut spam_ctx).await;
                    server.spam_filter_analyze_url(&mut spam_ctx).await;
                    server.spam_filter_analyze_rules(&mut spam_ctx).await;
                    spam_ctx.result.tags.retain(|t| !t.starts_with("X_HDR_"));
                }
                "mime" => {
                    server.spam_filter_analyze_mime(&mut spam_ctx).await;
                }
                "headers" => {
                    server.spam_filter_analyze_headers(&mut spam_ctx).await;
                    server.spam_filter_analyze_rules(&mut spam_ctx).await;
                    spam_ctx.result.tags.retain(|t| !t.starts_with("X_HDR_"));
                }
                "url" => {
                    server.spam_filter_analyze_url(&mut spam_ctx).await;
                    server.spam_filter_analyze_rules(&mut spam_ctx).await;
                }
                "dmarc" => {
                    server.spam_filter_analyze_dmarc(&mut spam_ctx).await;
                    server.spam_filter_analyze_headers(&mut spam_ctx).await;
                    server.spam_filter_analyze_rules(&mut spam_ctx).await;
                    spam_ctx.result.tags.retain(|t| !t.starts_with("X_HDR_"));
                }
                "ip" => {
                    server.spam_filter_analyze_ip(&mut spam_ctx).await;
                }
                "helo" => {
                    server.spam_filter_analyze_ehlo(&mut spam_ctx).await;
                }
                "bounce" => {
                    server.spam_filter_analyze_mime(&mut spam_ctx).await;
                    server.spam_filter_analyze_headers(&mut spam_ctx).await;
                    server.spam_filter_analyze_rules(&mut spam_ctx).await;
                    spam_ctx.result.tags.retain(|t| !t.starts_with("X_HDR_"));
                }
                "rbl" => {
                    server.spam_filter_analyze_url(&mut spam_ctx).await;
                    server.spam_filter_analyze_ip(&mut spam_ctx).await;
                    server.spam_filter_analyze_domain(&mut spam_ctx).await;
                }
                "spamtrap" => {
                    server.spam_filter_analyze_spam_trap(&mut spam_ctx).await;
                    server.spam_filter_finalize(&mut spam_ctx).await;
                }
                "classifier" => {
                    server.spam_filter_analyze_classify(&mut spam_ctx).await;
                    match server.spam_filter_finalize(&mut spam_ctx).await {
                        SpamFilterAction::Allow(r) => spam_ctx.result.tags.extend(
                            r.headers
                                .split_ascii_whitespace()
                                .filter(|t| t.starts_with("PROB_"))
                                .map(|t| t.to_string()),
                        ),
                        _ => unreachable!(),
                    }
                }
                "pyzor" => {
                    server.spam_filter_analyze_pyzor(&mut spam_ctx).await;
                }
                "llm" => {
                    server.spam_filter_analyze_llm(&mut spam_ctx).await;
                }
                _ => panic!("Invalid test {test_name:?}"),
            }

            // Compare tags
            if spam_ctx.result.tags != expected_tags {
                for tag in &spam_ctx.result.tags {
                    if !expected_tags.contains(tag) {
                        println!("Unexpected tag: {tag:?}");
                    }
                }

                for tag in &expected_tags {
                    if !spam_ctx.result.tags.contains(tag) {
                        println!("Missing tag: {tag:?}");
                    }
                }

                panic!("Tags mismatch, expected {expected_tags:?}");
            } else {
                println!("Tags matched: {expected_tags:?}");
            }
        }
    }
}

async fn classifier_features(server: &Server, contents: String) {
    let mut num_tests = 0;

    for test in contents.split("<!-- NEXT TEST -->") {
        let test = test.trim();
        if test.is_empty() {
            continue;
        }

        let (input, expected) = test.split_once("<!-- EXPECT -->").unwrap();
        let input = input.trim();
        let expected = expected.trim();

        // Build features
        let message = MessageParser::new().parse(input).unwrap_or_default();
        let mut ctx =
            server.spam_filter_init(SpamFilterInput::from_message(&message, 0).train_mode());
        server.spam_filter_analyze_domain(&mut ctx).await;
        server.spam_filter_analyze_url(&mut ctx).await;
        let mut tokens = server
            .spam_build_tokens(&ctx)
            .await
            .0
            .into_keys()
            .collect::<Vec<_>>();
        tokens.sort();

        assert!(!tokens.is_empty(), "No tokens parsed for input: {}", input);
        let expected_tokens: Vec<Token<'_>> = serde_json::from_str(expected).unwrap();

        if tokens != expected_tokens {
            eprintln!("Input: {}", input);
            eprintln!("Expected Tokens: {}", expected);
            eprintln!(
                "Parsed Tokens:   {}",
                serde_json::to_string_pretty(&tokens).unwrap()
            );
            panic!("Tokens do not match");
        }
        num_tests += 1;
    }

    assert_eq!(num_tests, 11, "Expected number of tests to run");
}

fn html_tokens(contents: String) {
    let mut num_tests = 0;

    for test in contents.split("<!-- NEXT TEST -->") {
        let test = test.trim();
        if test.is_empty() {
            continue;
        }

        let (input, expected) = test.split_once("<!-- EXPECT -->").unwrap();
        let input = input.trim();
        let expected = expected.trim();

        let tokens = html_to_tokens(input);
        assert!(!tokens.is_empty(), "No tokens parsed for input: {}", input);
        let expected_tokens: Vec<HtmlToken> = serde_json::from_str(expected).unwrap();

        assert_eq!(tokens, expected_tokens, "Input: {}", input);
        num_tests += 1;
    }

    assert_eq!(num_tests, 12, "Expected number of tests to run");
}

trait ParseConfigValue: Sized {
    fn from_str(value: &str) -> Self;
}

impl ParseConfigValue for SpfResult {
    fn from_str(value: &str) -> Self {
        match value {
            "pass" => SpfResult::Pass,
            "fail" => SpfResult::Fail,
            "softfail" => SpfResult::SoftFail,
            "neutral" => SpfResult::Neutral,
            "none" => SpfResult::None,
            "temperror" => SpfResult::TempError,
            "permerror" => SpfResult::PermError,
            _ => panic!("Invalid SPF result"),
        }
    }
}

impl ParseConfigValue for IprevResult {
    fn from_str(value: &str) -> Self {
        match value {
            "pass" => IprevResult::Pass,
            "fail" => IprevResult::Fail(mail_auth::Error::NotAligned),
            "temperror" => IprevResult::TempError(mail_auth::Error::NotAligned),
            "permerror" => IprevResult::PermError(mail_auth::Error::NotAligned),
            "none" => IprevResult::None,
            _ => panic!("Invalid IPREV result"),
        }
    }
}

impl ParseConfigValue for DkimResult {
    fn from_str(value: &str) -> Self {
        match value {
            "pass" => DkimResult::Pass,
            "none" => DkimResult::None,
            "neutral" => DkimResult::Neutral(mail_auth::Error::NotAligned),
            "fail" => DkimResult::Fail(mail_auth::Error::NotAligned),
            "permerror" => DkimResult::PermError(mail_auth::Error::NotAligned),
            "temperror" => DkimResult::TempError(mail_auth::Error::NotAligned),
            _ => panic!("Invalid DKIM result"),
        }
    }
}

impl ParseConfigValue for DmarcResult {
    fn from_str(value: &str) -> Self {
        match value {
            "pass" => DmarcResult::Pass,
            "fail" => DmarcResult::Fail(mail_auth::Error::NotAligned),
            "temperror" => DmarcResult::TempError(mail_auth::Error::NotAligned),
            "permerror" => DmarcResult::PermError(mail_auth::Error::NotAligned),
            "none" => DmarcResult::None,
            _ => panic!("Invalid DMARC result"),
        }
    }
}

impl ParseConfigValue for Policy {
    fn from_str(value: &str) -> Self {
        match value {
            "reject" => Policy::Reject,
            "quarantine" => Policy::Quarantine,
            "none" => Policy::None,
            _ => panic!("Invalid DMARC policy"),
        }
    }
}
