/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{
    containers::{Litmus, LitmusRun},
    server::TestServerBuilder,
};
use ahash::AHashMap;
use registry::schema::enums::{NetworkListenerProtocol, Permission};
use std::{path::PathBuf, time::Instant};

pub const HTTP_PORT: u16 = 8905;
pub const PLAIN_HTTP_PORT: u16 = 8906;

const USER: &str = "litmus@example.com";
const PASSWORD: &str = "litmus_secret_with_extra_safety";

const SUITES: [&str; 5] = ["basic", "copymove", "props", "locks", "http"];

const KNOWN_FAILURES: &[(&str, &str)] = &[];

#[tokio::test(flavor = "multi_thread")]
pub async fn webdav_compliance_tests() {
    let mut test = TestServerBuilder::new("webdav_compliance_tests")
        .await
        .with_listener(
            NetworkListenerProtocol::Http,
            "litmus",
            PLAIN_HTTP_PORT,
            false,
        )
        .await
        .with_http_listener(HTTP_PORT)
        .await
        .build()
        .await;

    let admin = test.create_admin_account("admin@example.com").await;
    let account = admin
        .create_user_account(
            USER,
            PASSWORD,
            "Litmus User",
            &[],
            vec![Permission::UnlimitedRequests, Permission::UnlimitedUploads],
        )
        .await;
    test.insert_account(account);
    test.insert_account(admin);

    let start_time = Instant::now();
    let litmus = Litmus::start().await;
    let url = format!(
        "http://host.docker.internal:{PLAIN_HTTP_PORT}/dav/file/{}/",
        USER.replace('@', "%40")
    );
    let logs_dir = logs_dir();

    let mut failed = Vec::new();
    let mut unexplained = Vec::new();
    for suite in SUITES {
        let run = litmus.run_suite(suite, &url, USER, PASSWORD).await;
        println!("--- litmus {suite} ---\n{}", printable(&run.stdout));

        let outcomes = outcomes(&run.stdout);
        let suite_failures: Vec<_> = outcomes
            .iter()
            .filter(|outcome| outcome.status == Status::Failed)
            .map(|outcome| format!("{suite}/{}", outcome.test))
            .collect();

        if !suite_failures.is_empty() || run.exit_code != 0 {
            let log_path = logs_dir.join(format!("{suite}.log"));
            std::fs::write(&log_path, litmus.debug_log().await)
                .expect("Failed to write the litmus debug log");
            println!("litmus {suite} debug log: {}", log_path.display());
        }

        if suite_failures.is_empty() && run.exit_code != 0 {
            unexplained.push(unexplained_exit(suite, &run));
        }
        failed.extend(suite_failures);
    }

    let mut report = assess(&failed);
    report.extend(unexplained);
    if !report.is_empty() {
        panic!("{}", report.join("\n\n"));
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

#[derive(Debug, PartialEq, Eq)]
enum Status {
    Passed,
    Failed,
    Skipped,
    Pending,
}

struct Outcome<'x> {
    test: &'x str,
    status: Status,
}

fn outcomes(stdout: &str) -> Vec<Outcome<'_>> {
    let mut outcomes: Vec<Outcome<'_>> = Vec::new();
    for segment in stdout.split(['\n', '\r']).map(str::trim_start) {
        let Some((head, status)) = segment.split_once(' ') else {
            continue;
        };
        if head.starts_with('.') {
            if let Some(last) = outcomes.last_mut() {
                last.status = Status::parse(status);
            }
        } else if head.strip_suffix('.').is_some_and(is_number)
            && let Some((test, status)) = status.split_once(' ')
        {
            outcomes.push(Outcome {
                test: test.trim_end_matches('.'),
                status: Status::parse(status),
            });
        }
    }
    outcomes
}

impl Status {
    fn parse(status: &str) -> Self {
        let status = status.trim_start_matches("fatal error - ");
        if status.starts_with("FAIL") {
            Status::Failed
        } else if status.starts_with("SKIPPED") {
            Status::Skipped
        } else if status.starts_with("pass") || status.starts_with("XFAIL") {
            Status::Passed
        } else {
            Status::Pending
        }
    }
}

fn is_number(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn assess(failed: &[String]) -> Vec<String> {
    let baseline: AHashMap<&str, &str> = KNOWN_FAILURES.iter().copied().collect();
    let mut report = Vec::new();

    let regressions: Vec<&str> = failed
        .iter()
        .map(String::as_str)
        .filter(|test| !baseline.contains_key(test))
        .collect();
    if !regressions.is_empty() {
        report.push(format!(
            "litmus reported {} failing test(s) that are not in KNOWN_FAILURES in \
             tests/src/webdav/compliance.rs:\n  {}",
            regressions.len(),
            regressions.join("\n  ")
        ));
    }

    let mut fixed: Vec<String> = baseline
        .iter()
        .filter(|(test, _)| !failed.iter().any(|failed| failed == *test))
        .map(|(test, reason)| format!("{test} ({reason})"))
        .collect();
    fixed.sort();
    if !fixed.is_empty() {
        report.push(format!(
            "litmus passed {} test(s) that are still listed as known failures. \
             Remove them from KNOWN_FAILURES in tests/src/webdav/compliance.rs:\n  {}",
            fixed.len(),
            fixed.join("\n  ")
        ));
    }

    report
}

fn unexplained_exit(suite: &str, run: &LitmusRun) -> String {
    format!(
        "litmus {suite} exited with {} but named no failing test.\n\nstdout:\n{}\n\nstderr:\n{}",
        run.exit_code,
        printable(&run.stdout),
        run.stderr.trim_end()
    )
}

fn printable(stdout: &str) -> String {
    stdout
        .split('\n')
        .filter_map(|line| line.rsplit('\r').find(|part| !part.is_empty()))
        .collect::<Vec<_>>()
        .join("\n")
}

fn logs_dir() -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push("webdav_compliance_litmus");
    std::fs::create_dir_all(&path).expect("Failed to create the litmus log directory");
    path
}
