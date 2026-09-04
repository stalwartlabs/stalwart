/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{
    containers::{IMAPTEST_TESTS_DIR, ImapTest, ImapTestRun},
    server::TestServerBuilder,
};
use ahash::{AHashMap, AHashSet};
use registry::schema::{enums::Permission, structs::Imap};
use std::{path::PathBuf, time::Instant};

pub const HTTP_PORT: u16 = 8903;
pub const IMAP_PORT: u16 = 9993;

const USER: &str = "imaptest@example.com";
const USER2: &str = "imaptest2@example.com";
const PASSWORD: &str = "imaptest_secret_with_extra_safety";

const KNOB_VARS: [&str; 8] = [
    "IMAP_RECENT",
    "IMAP_UNSEEN_RESPONSE",
    "IMAP_FTS_SUBSTRING",
    "IMAP_SORT_ADDRESS_KEYS",
    "IMAP_SENT_DATE_HEADER",
    "IMAP_FTS_SYNC",
    "IMAP_SORT_BASE_SUBJECT",
    "IMAP_THREAD_REFERENCES",
];

const REV2_BLOCKER: Option<&str> = None;

const KNOWN_FAILURES: &[(&str, &str)] = &[
    (
        "append-binary",
        "imaptest cannot express this fixture: its parser measures command lines with strlen (test-parser.c), so the banned literal, which begins with a NUL octet, truncates to an empty {0} pattern that then matches any reply. Verified against the server directly: FETCH BODY[1] returns {7} with the NUL intact, alongside BINARY.SIZE[1] 7",
    ),
    (
        "listext",
        "RFC 3501 6.3.9: a subscribed mailbox that has been deleted is dropped from LIST (SUBSCRIBED) instead of being returned \\Subscribed \\NonExistent. Subscriptions live on the mailbox object, so deleting it destroys the record; keeping subscriber ids for deleted mailboxes was judged not worth the cost",
    ),
    (
        "move",
        "MOVE onto the selected mailbox is rejected with NO [CANNOT]. RFC 6851 3 defines it as COPY plus EXPUNGE, but a message cannot be held twice by one mailbox here and the degenerate self-move was judged not worth the complexity",
    ),
    (
        "search-addresses",
        "RFC 9051 6.4.4 requires substring matching for FROM/TO/CC/BCC, and a zero-length HEADER value must match every message carrying that header. Supporting substrings across every backing FTS store was judged out of scope",
    ),
    (
        "search-body",
        "RFC 9051 6.4.4 defines TEXT as the header plus the body, but TEXT only covers the indexed From/To/Cc/Bcc/Subject/Body/Attachment fields, so a match in any other header is missed",
    ),
    (
        "search-header",
        "RFC 9051 6.4.4 requires substring matching, and a zero-length HEADER value must match every message carrying that header. Subject/From/To/Cc/Bcc are indexed as text rather than into the Headers key-value index, so neither works for them",
    ),
];

const REV2_EXTRA_FAILURES: &[(&str, &str)] = &[
    (
        "close",
        "The fixture expects an untagged EXPUNGE. imaptest's imap4rev2 flag also enables QRESYNC, and RFC 7162 3.2.10 then requires VANISHED instead of EXPUNGE for the rest of the connection",
    ),
    (
        "expunge",
        "The fixture expects an untagged EXPUNGE, which RFC 7162 3.2.10 replaces with VANISHED once QRESYNC is enabled",
    ),
    (
        "expunge2",
        "The fixture expects an untagged EXPUNGE, which RFC 7162 3.2.10 replaces with VANISHED once QRESYNC is enabled",
    ),
    (
        "fetch",
        "The fixture expects an untagged EXPUNGE, which RFC 7162 3.2.10 replaces with VANISHED once QRESYNC is enabled",
    ),
    (
        "nil",
        "The fixture expects an untagged SEARCH, which IMAP4rev2 returns as ESEARCH (RFC 9051 appendix E item 4)",
    ),
    (
        "search-date",
        "The fixture expects an untagged SEARCH. RFC 9051 appendix E item 4 deprecates it, and a IMAP4rev2 SEARCH returns ESEARCH instead",
    ),
    (
        "search-flags",
        "The fixture expects an untagged SEARCH, which IMAP4rev2 returns as ESEARCH (RFC 9051 appendix E item 4)",
    ),
    (
        "search-sets",
        "The fixture expects an untagged SEARCH, which IMAP4rev2 returns as ESEARCH (RFC 9051 appendix E item 4)",
    ),
    (
        "search-size",
        "The fixture expects an untagged SEARCH, which IMAP4rev2 returns as ESEARCH (RFC 9051 appendix E item 4)",
    ),
];

#[tokio::test(flavor = "multi_thread")]
pub async fn imap_compliance_tests() {
    let mut test = TestServerBuilder::new("imap_compliance_tests")
        .await
        .with_http_listener(HTTP_PORT)
        .await
        .with_imap_listener(IMAP_PORT)
        .await
        .build()
        .await;

    let admin = test.create_admin_account("admin@example.com").await;
    for name in [USER, USER2] {
        let account = admin
            .create_user_account(
                name,
                PASSWORD,
                "ImapTest User",
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

    let start_time = Instant::now();
    let imaptest = ImapTest::start(&fixtures_dir()).await;
    let env = knobs();

    let mut failures = Vec::new();
    for (label, protocol, blocker, extra) in [
        ("IMAP4rev1", None, None, &[][..]),
        (
            "IMAP4rev2",
            Some("imap4rev2"),
            REV2_BLOCKER,
            REV2_EXTRA_FAILURES,
        ),
    ] {
        let mut args = vec![
            format!("test={IMAPTEST_TESTS_DIR}"),
            "host=host.docker.internal".to_string(),
            format!("port={IMAP_PORT}"),
            format!("user={USER}"),
            format!("user2={USER2}"),
            format!("pass={PASSWORD}"),
            "no_tracking".to_string(),
        ];
        args.extend(protocol.map(str::to_string));

        let run = imaptest.run(&args, &env).await;
        println!("--- imaptest {label} ---\n{}", run.stdout.trim_end());
        failures.extend(assess(label, &run, blocker, extra));
    }

    if !failures.is_empty() {
        panic!("{}", failures.join("\n\n"));
    }

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

fn assess(
    label: &str,
    run: &ImapTestRun,
    blocker: Option<&str>,
    extra: &[(&str, &str)],
) -> Vec<String> {
    let failed = failed_groups(&run.stderr);

    if let Some(blocker) = blocker {
        return if is_login_blocked(&run.stderr) {
            println!("imaptest {label} never got past login: {blocker}");
            Vec::new()
        } else {
            vec![format!(
                "imaptest {label} is no longer blocked at login. Clear REV2_BLOCKER in \
                 tests/src/imap/compliance.rs so this pass is compared against KNOWN_FAILURES."
            )]
        };
    }

    let baseline: AHashMap<&str, &str> = KNOWN_FAILURES.iter().chain(extra).copied().collect();
    let mut report = Vec::new();

    let mut regressions: Vec<&str> = failed
        .iter()
        .copied()
        .filter(|group| !baseline.contains_key(group))
        .collect();
    regressions.sort_unstable();
    if !regressions.is_empty() {
        report.push(format!(
            "imaptest {label} reported {} failing test group(s) that are not in KNOWN_FAILURES in \
             tests/src/imap/compliance.rs:\n  {}\n\nimaptest stderr:\n{}",
            regressions.len(),
            regressions.join("\n  "),
            run.stderr.trim_end()
        ));
    }

    let mut fixed: Vec<String> = baseline
        .iter()
        .filter(|(group, _)| !failed.contains(*group))
        .map(|(group, reason)| format!("{group} ({reason})"))
        .collect();
    fixed.sort();
    if !fixed.is_empty() {
        report.push(format!(
            "imaptest {label} passed {} test group(s) that are still listed as known failures. \
             Remove them from KNOWN_FAILURES in tests/src/imap/compliance.rs:\n  {}",
            fixed.len(),
            fixed.join("\n  ")
        ));
    }

    if failed.is_empty() && run.exit_code != 0 {
        report.push(format!(
            "imaptest {label} exited with {} but named no failing test group.\n\nstdout:\n{}\n\nstderr:\n{}",
            run.exit_code,
            run.stdout.trim_end(),
            run.stderr.trim_end()
        ));
    }

    report
}

fn is_login_blocked(stderr: &str) -> bool {
    stderr
        .lines()
        .filter(|line| line.contains("LOGIN failed:"))
        .count()
        > KNOWN_FAILURES.len()
}

fn failed_groups(stderr: &str) -> AHashSet<&str> {
    stderr
        .lines()
        .filter_map(|line| line.strip_prefix("*** Test "))
        .filter_map(|rest| rest.split_whitespace().next())
        .collect()
}

fn knobs() -> Vec<(&'static str, &'static str)> {
    KNOB_VARS
        .iter()
        .filter(|name| std::env::var(*name).is_ok_and(|value| value == "1"))
        .map(|name| (*name, "1"))
        .collect()
}

pub fn fixtures_dir() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("resources");
    path.push("imap-test");
    path
}
