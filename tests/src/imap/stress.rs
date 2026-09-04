/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    imap::compliance::fixtures_dir,
    utils::{
        containers::{IMAPTEST_TESTS_DIR, ImapTest},
        server::TestServerBuilder,
    },
};
use ahash::AHashSet;
use registry::schema::{enums::Permission, structs::Imap};
use std::time::{Duration, Instant};

pub const HTTP_PORT: u16 = 8904;
pub const IMAP_PORT: u16 = 9994;

const USER_TEMPLATE: &str = "stress%d@example.com";
const PASSWORD: &str = "imapstress_secret_with_extra_safety";

const DEFAULT_CLIENTS: u32 = 10;
const DEFAULT_SECS: u64 = 30;
const DEFAULT_MSGS: u32 = 30;
const DEFAULT_USERS: u32 = 4;
const DEFAULT_ARGS: &str = "no_tracking";

const GRACE: Duration = Duration::from_secs(120);

const KNOWN_ERRORS: &[(&str, &str)] = &[
    (
        "seq too high",
        "an unsolicited FETCH names a sequence number the client was never told about, the untagged EXISTS for the new message is missing or late",
    ),
    (
        "Keyword used without being in FLAGS",
        "the untagged FLAGS reply is a fixed list of the five system flags, mailbox keywords are never advertised",
    ),
    (
        "Referenced message expunged",
        "RFC 9051 7.5.1 forbids an EXPUNGE while a FETCH on that message is in progress",
    ),
    (
        "EXPUNGE failed",
        "EXPUNGE returns NO [CONTACTADMIN] Internal Server Error under concurrent access",
    ),
    (
        "Missing flags to set",
        "RFC 9051 flag-list allows an empty list, so STORE -FLAGS () is a valid no-op and must not be rejected with BAD",
    ),
    (
        "Invalid untagged input",
        "follow-on error, imaptest reports this after it has already rejected the untagged reply for one of the reasons above",
    ),
];

#[tokio::test(flavor = "multi_thread")]
pub async fn imap_stress_test() {
    let clients = env_num("IMAP_STRESS_CLIENTS", DEFAULT_CLIENTS);
    let secs = env_num("IMAP_STRESS_SECS", DEFAULT_SECS);
    let msgs = env_num("IMAP_STRESS_MSGS", DEFAULT_MSGS);
    let users = env_num("IMAP_STRESS_USERS", DEFAULT_USERS);
    let mbox = std::env::var("IMAP_STRESS_MBOX")
        .unwrap_or_else(|_| format!("{IMAPTEST_TESTS_DIR}/default.mbox"));
    let extra = std::env::var("IMAP_STRESS_ARGS").unwrap_or_else(|_| DEFAULT_ARGS.to_string());

    assert!(users > 0, "IMAP_STRESS_USERS must be at least 1");

    let mut test = TestServerBuilder::new("imap_stress_test")
        .await
        .with_http_listener(HTTP_PORT)
        .await
        .with_imap_listener(IMAP_PORT)
        .await
        .build()
        .await;

    let admin = test.create_admin_account("admin@example.com").await;
    for index in 1..=users {
        let name: &'static str = Box::leak(
            USER_TEMPLATE
                .replace("%d", &index.to_string())
                .into_boxed_str(),
        );
        let account = admin
            .create_user_account(
                name,
                PASSWORD,
                "ImapTest Stress User",
                &[],
                vec![Permission::UnlimitedRequests, Permission::UnlimitedUploads],
            )
            .await;
        test.insert_account(account);
    }
    admin
        .registry_create_object(Imap {
            allow_plain_text_auth: true,
            ..Default::default()
        })
        .await;
    admin.reload_settings().await;
    test.insert_account(admin);

    let mut args = vec![
        "host=host.docker.internal".to_string(),
        format!("port={IMAP_PORT}"),
        format!("user={USER_TEMPLATE}"),
        format!("users=1-{users}"),
        format!("pass={PASSWORD}"),
        format!("clients={clients}"),
        format!("secs={secs}"),
        format!("msgs={msgs}"),
        format!("mbox={mbox}"),
    ];
    if let Ok(seed) = std::env::var("IMAP_STRESS_SEED") {
        args.push(format!("seed={seed}"));
    }
    args.extend(extra.split_whitespace().map(str::to_string));

    println!("Running imaptest {}", args.join(" "));

    let start_time = Instant::now();
    let imaptest = ImapTest::start(&fixtures_dir()).await;
    let run = tokio::time::timeout(Duration::from_secs(secs) + GRACE, imaptest.run(&args, &[]))
        .await
        .expect("imaptest did not finish within the stress budget");

    println!("--- imaptest stress ---\n{}", run.stdout.trim_end());

    let mut unknown: Vec<&str> = run
        .stderr
        .lines()
        .filter(|line| {
            line.starts_with("Panic:") || (line.starts_with("Error: ") && line.contains("]: "))
        })
        .filter(|line| !KNOWN_ERRORS.iter().any(|(kind, _)| line.contains(kind)))
        .map(|line| line.split_once("]: ").map_or(line, |(_, rest)| rest))
        .collect::<AHashSet<_>>()
        .into_iter()
        .collect();
    unknown.sort_unstable();

    assert!(
        unknown.is_empty(),
        "imaptest reported {} error kind(s) that are not in KNOWN_ERRORS in \
         tests/src/imap/stress.rs:\n{}",
        unknown.len(),
        unknown.join("\n")
    );

    for (kind, reason) in KNOWN_ERRORS {
        let hits = run.stderr.lines().filter(|l| l.contains(kind)).count();
        if hits > 0 {
            println!("  {hits} x {kind}: {reason}");
        }
    }

    assert_eq!(
        run.exit_code,
        0,
        "imaptest exited with {}.\n\nstdout:\n{}\n\nstderr:\n{}",
        run.exit_code,
        run.stdout.trim_end(),
        run.stderr.trim_end()
    );

    let elapsed = start_time.elapsed();
    println!(
        "Elapsed: {}.{:03}s",
        elapsed.as_secs(),
        elapsed.subsec_millis()
    );

    if test.is_reset() {
        test.temp_dir.delete();
    }
}

fn env_num<T: std::str::FromStr>(name: &str, default: T) -> T {
    match std::env::var(name) {
        Ok(value) => value
            .parse()
            .unwrap_or_else(|_| panic!("Invalid {name} value: {value}")),
        Err(_) => default,
    }
}
