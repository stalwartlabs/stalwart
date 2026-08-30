/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    scim::{SCIM_DOMAIN, ScimTest},
    utils::containers,
};
use ahash::AHashMap;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::Value;

const DRIVER: &str = include_str!("../../docker/scim/driver.py");

const URL: &str = "https://host.docker.internal:8899/scim/v2";
const NON_MAILBOX_USER_NAME: &str = "is not a valid email address";
const STRICT_TAGS: [&str; 5] = [
    "discovery",
    "service-provider-config",
    "resource-types",
    "schemas",
    "misc",
];

pub fn is_enabled() -> bool {
    std::env::var("SCIM_CONFORMANCE").is_ok_and(|value| value == "1")
}

pub async fn test(scim: &ScimTest) {
    println!("Running SCIM third party conformance tests...");
    containers::ensure_scim_tester().await;

    the_lifecycle_survives_a_third_party_client(scim).await;
    real_client_payloads_are_accepted(scim).await;
    the_conformance_checker_reports_no_failures(scim).await;
}

async fn real_client_payloads_are_accepted(scim: &ScimTest) {
    let report = run(scim, "clients").await;
    let steps = report["steps"]
        .as_array()
        .unwrap_or_else(|| panic!("Missing steps in {report}"));

    assert!(!steps.is_empty(), "The driver ran no steps: {report}");
    for step in steps {
        if step["ok"] != Value::Bool(true) {
            panic!(
                "The {} payload was refused:\n{}",
                step["step"].as_str().unwrap_or_default(),
                step["detail"].as_str().unwrap_or_default()
            );
        }
    }

    println!("  replayed {} real client payloads", steps.len());
}

async fn the_lifecycle_survives_a_third_party_client(scim: &ScimTest) {
    let report = run(scim, "lifecycle").await;
    let steps = report["steps"]
        .as_array()
        .unwrap_or_else(|| panic!("Missing steps in {report}"));

    assert!(!steps.is_empty(), "The driver ran no steps: {report}");
    for step in steps {
        if step["ok"] != Value::Bool(true) {
            panic!(
                "scim2-client step '{}' failed:\n{}",
                step["step"].as_str().unwrap_or_default(),
                step["detail"].as_str().unwrap_or_default()
            );
        }
    }

    println!("  scim2-client completed {} lifecycle steps", steps.len());
}

async fn the_conformance_checker_reports_no_failures(scim: &ScimTest) {
    let report = run(scim, "conformance").await;
    let checks = report["checks"]
        .as_array()
        .unwrap_or_else(|| panic!("Missing checks in {report}"));

    assert!(!checks.is_empty(), "The checker ran no checks: {report}");

    let mut totals: AHashMap<String, usize> = AHashMap::new();
    let mut expected = 0;
    let mut failures = Vec::new();
    let mut strict_checks = 0;

    for check in checks {
        let status = check["status"].as_str().unwrap_or_default();
        let reason = check["reason"].as_str().unwrap_or_default();
        let title = check["title"].as_str().unwrap_or_default();
        let tags = check["tags"]
            .as_array()
            .map(|tags| {
                tags.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        *totals.entry(status.to_string()).or_default() += 1;
        if tags.iter().any(|tag| STRICT_TAGS.contains(&tag.as_str())) {
            strict_checks += 1;
        }

        if !matches!(status, "ERROR" | "CRITICAL" | "DEVIATION") {
            continue;
        }

        if status == "ERROR" && reason.contains(NON_MAILBOX_USER_NAME) {
            expected += 1;
            continue;
        }

        failures.push(format!(
            "  [{status}] {title} ({}): {reason}",
            tags.join(",")
        ));
    }

    let mut summary = totals.into_iter().collect::<Vec<_>>();
    summary.sort();
    println!(
        "  scim2-tester ran {} checks ({strict_checks} of them on the discovery endpoints): {}",
        checks.len(),
        summary
            .iter()
            .map(|(status, count)| format!("{status}={count}"))
            .collect::<Vec<_>>()
            .join(" ")
    );
    println!("  {expected} checks failed because the generated userName is not a mailbox address");

    assert!(
        failures.is_empty(),
        "scim2-tester reported unexplained failures:\n{}",
        failures.join("\n")
    );
    assert!(
        strict_checks > 0,
        "The checker ran no discovery checks: {report}"
    );
}

async fn run(scim: &ScimTest, mode: &str) -> Value {
    let command = format!(
        "echo '{}' | base64 -d > /tmp/driver.py && exec python /tmp/driver.py \
         --url {URL} --token {} --domain {SCIM_DOMAIN} --mode {mode}",
        STANDARD.encode(DRIVER.as_bytes()),
        scim.token,
    );
    let (stdout, stderr) = containers::scim_tester_exec(&["sh", "-c", &command]).await;

    let report = stdout
        .lines()
        .rev()
        .find(|line| line.starts_with('{'))
        .unwrap_or_else(|| {
            panic!("The SCIM driver produced no report.\nstdout:\n{stdout}\nstderr:\n{stderr}")
        });

    let report = serde_json::from_str::<Value>(report).unwrap_or_else(|err| {
        panic!("The SCIM driver report is not valid JSON: {err}\n{stdout}\n{stderr}")
    });

    if let Some(error) = report.get("error").and_then(Value::as_str) {
        panic!("The SCIM driver failed: {error}");
    }

    report
}
