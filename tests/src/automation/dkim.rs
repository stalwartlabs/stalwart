/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{account::Account, server::TestServer};
use ahash::AHashSet;
use common::{config::smtp::auth::Dkim1Signer, network::dns::update::DNS_RECORDS};
use dns_update::{DnsRecord, NamedDnsRecord};
use registry::{
    schema::{
        enums::{DkimRotationStage, DnsRecordType, IpProtocol, TsigAlgorithm},
        prelude::{ObjectType, Property},
        structs::{
            CertificateManagement, Dkim1Signature, DkimManagement, DkimManagementProperties,
            DkimSignature, DnsManagement, DnsManagementProperties, DnsServer, DnsServerCloudflare,
            DnsServerTsig, Domain, SecretKey, SecretKeyValue, Task, TaskDomainManagement,
            TaskManager, TaskRetryStrategy, TaskRetryStrategyFixed, TaskStatus,
        },
    },
    types::{duration::Duration, map::Map},
};
use serde_json::json;
use store::write::now;
use types::id::Id;

const SHORT_ROTATION_MS: u64 = 6_000;
const LONG_ROTATION_MS: u64 = 3_600_000;

pub async fn test(test: &TestServer) {
    fast_retry_tests(test).await;
    unscheduled_keys_test(test, "dkim-manual.org", |_| DnsManagement::Manual).await;
    unscheduled_keys_test(test, "dkim-unpublished.org", |dns_server_id| {
        DnsManagement::Automatic(DnsManagementProperties {
            dns_server_id,
            publish_records: Map::new(vec![DnsRecordType::Spf]),
            ..Default::default()
        })
    })
    .await;
    automatic_to_manual_dns_test(test).await;

    println!("Running DKIM Management tests...");
    let account = test.account("admin@example.org");
    DNS_RECORDS.lock().unwrap().clear();

    // Create test In Memory DNS servers
    let dns_server_id = account
        .registry_create_object(DnsServer::Cloudflare(DnsServerCloudflare {
            secret: SecretKey::Value(SecretKeyValue {
                secret: "test@memory.org".into(),
            }),
            description: "In-memory DNS server".to_string(),
            ..Default::default()
        }))
        .await;
    account.dkim_signatures().await.assert_total(0, 0);

    // Create a domain and trigger DKIM key generation
    let now = now();
    let selector_rsa = format!("dummy-v1-rsa-{}", now);
    let selector_ed = format!("dummy-v1-ed25519-{}", now);
    let domain_id = account
        .registry_create_object(Domain {
            name: "dkim.org".to_string(),
            certificate_management: CertificateManagement::Manual,
            dkim_management: DkimManagement::Automatic(DkimManagementProperties {
                delete_after: Duration::from_millis(2_000),
                retire_after: Duration::from_millis(2_000),
                rotate_after: Duration::from_millis(2_000),
                selector_template: "dummy-v{version}-{algorithm}-{epoch}".to_string(),
                ..Default::default()
            }),
            dns_management: DnsManagement::Automatic(DnsManagementProperties {
                dns_server_id,
                ..Default::default()
            }),
            ..Default::default()
        })
        .await;

    // Make sure two DKIM keys were created
    let rot1_signatures = account
        .wait_for_dkim_signatures(&DkimSignatures::default(), 2)
        .await
        .assert_total(1, 1)
        .assert_stage_count(DkimRotationStage::Active, 2);
    assert_eq!(
        rot1_signatures.v1_rsa[0].selector, selector_rsa,
        "Unexpected RSA selector: {}",
        rot1_signatures.v1_rsa[0].selector
    );
    assert_eq!(
        rot1_signatures.v1_ed25519[0].selector, selector_ed,
        "Unexpected Ed25519 selector: {}",
        rot1_signatures.v1_ed25519[0].selector
    );
    assert_eq!(
        rot1_signatures.v1_rsa[0]
            .next_transition_at
            .unwrap()
            .timestamp()
            - rot1_signatures.v1_rsa[0].created_at.timestamp(),
        2
    );
    test.assert_has_signers(
        "dkim.org",
        &[
            &rot1_signatures.v1_rsa[0].selector,
            &rot1_signatures.v1_ed25519[0].selector,
        ],
    )
    .await;

    // Make sure the DNS records were created
    let records = DNS_RECORDS.lock().unwrap().clone();
    assert_key_has_dns_record(&records, "dkim.org", &rot1_signatures.v1_rsa[0]);
    assert_key_has_dns_record(&records, "dkim.org", &rot1_signatures.v1_ed25519[0]);

    // Expect a rotation to happen and new keys to be created
    let rot2_signatures = account
        .wait_for_dkim_signatures(&rot1_signatures, 4)
        .await
        .assert_total(2, 2)
        .assert_stage_count(DkimRotationStage::Active, 2)
        .assert_stage_count(DkimRotationStage::Retiring, 2);

    // Make sure both old and new keys have DNS records
    let records = DNS_RECORDS.lock().unwrap().clone();
    assert_key_has_dns_record(&records, "dkim.org", &rot1_signatures.v1_rsa[0]);
    assert_key_has_dns_record(&records, "dkim.org", &rot1_signatures.v1_ed25519[0]);
    assert_key_has_dns_record(&records, "dkim.org", &rot2_signatures.v1_rsa[0]);
    assert_key_has_dns_record(&records, "dkim.org", &rot2_signatures.v1_ed25519[0]);

    // Make sure only the new keys are being used for signing
    assert_ne!(
        rot1_signatures.v1_rsa[0].selector, rot2_signatures.v1_rsa[0].selector,
        "Expected a new RSA selector to be generated during rotation"
    );
    assert_ne!(
        rot1_signatures.v1_ed25519[0].selector, rot2_signatures.v1_ed25519[0].selector,
        "Expected a new Ed25519 selector to be generated during rotation"
    );
    test.assert_has_signers(
        "dkim.org",
        &[
            &rot2_signatures.v1_rsa[0].selector,
            &rot2_signatures.v1_ed25519[0].selector,
        ],
    )
    .await;

    // Wait until the previous key is retired
    let rot3_signatures = account
        .wait_for_dkim_signatures(&rot2_signatures, 6)
        .await
        .assert_total(3, 3)
        .assert_stage_count(DkimRotationStage::Active, 2)
        .assert_stage_count(DkimRotationStage::Retiring, 2)
        .assert_stage_count(DkimRotationStage::Retired, 2);

    // Make sure the old records were deleted
    let records = DNS_RECORDS.lock().unwrap().clone();
    assert_key_has_no_dns_record(&records, "dkim.org", &rot1_signatures.v1_rsa[0]);
    assert_key_has_no_dns_record(&records, "dkim.org", &rot1_signatures.v1_ed25519[0]);
    assert_key_has_dns_record(&records, "dkim.org", &rot2_signatures.v1_rsa[0]);
    assert_key_has_dns_record(&records, "dkim.org", &rot2_signatures.v1_ed25519[0]);
    assert_key_has_dns_record(&records, "dkim.org", &rot3_signatures.v1_rsa[0]);
    assert_key_has_dns_record(&records, "dkim.org", &rot3_signatures.v1_ed25519[0]);

    // Make sure the DNS management task does not republish the retired keys
    let (published, zone_file) = test.published_dkim_records(domain_id).await;
    assert_key_has_no_dns_record(&published, "dkim.org", &rot1_signatures.v1_rsa[0]);
    assert_key_has_no_dns_record(&published, "dkim.org", &rot1_signatures.v1_ed25519[0]);
    assert_key_has_dns_record(&published, "dkim.org", &rot3_signatures.v1_rsa[0]);
    assert_key_has_dns_record(&published, "dkim.org", &rot3_signatures.v1_ed25519[0]);
    assert_zone_file_omits_key(&zone_file, &rot1_signatures.v1_rsa[0]);
    assert_zone_file_omits_key(&zone_file, &rot1_signatures.v1_ed25519[0]);

    // Make sure only the new keys are being used for signing
    assert_ne!(
        rot2_signatures.v1_rsa[0].selector, rot3_signatures.v1_rsa[0].selector,
        "Expected a new RSA selector to be generated during rotation"
    );
    assert_ne!(
        rot2_signatures.v1_ed25519[0].selector, rot3_signatures.v1_ed25519[0].selector,
        "Expected a new Ed25519 selector to be generated during rotation"
    );
    test.assert_has_signers(
        "dkim.org",
        &[
            &rot3_signatures.v1_rsa[0].selector,
            &rot3_signatures.v1_ed25519[0].selector,
        ],
    )
    .await;

    // Wait until the first key is deleted
    let rot4_signatures = account
        .wait_for_dkim_signatures(&rot3_signatures, 6)
        .await
        .assert_total(3, 3)
        .assert_stage_count(DkimRotationStage::Active, 2)
        .assert_stage_count(DkimRotationStage::Retiring, 2)
        .assert_stage_count(DkimRotationStage::Retired, 2)
        .assert_selector_missing(&rot1_signatures.v1_rsa[0].selector)
        .assert_selector_missing(&rot1_signatures.v1_ed25519[0].selector);

    // Make sure the old records were updated
    let records = DNS_RECORDS.lock().unwrap().clone();
    assert_key_has_dns_record(&records, "dkim.org", &rot4_signatures.v1_rsa[0]);
    assert_key_has_dns_record(&records, "dkim.org", &rot4_signatures.v1_ed25519[0]);
    assert_key_has_no_dns_record(&records, "dkim.org", &rot2_signatures.v1_rsa[0]);
    assert_key_has_no_dns_record(&records, "dkim.org", &rot2_signatures.v1_ed25519[0]);

    // Make sure the DNS management task does not republish the retired keys
    let (published, zone_file) = test.published_dkim_records(domain_id).await;
    assert_key_has_no_dns_record(&published, "dkim.org", &rot2_signatures.v1_rsa[0]);
    assert_key_has_no_dns_record(&published, "dkim.org", &rot2_signatures.v1_ed25519[0]);
    assert_key_has_dns_record(&published, "dkim.org", &rot4_signatures.v1_rsa[0]);
    assert_key_has_dns_record(&published, "dkim.org", &rot4_signatures.v1_ed25519[0]);
    assert_zone_file_omits_key(&zone_file, &rot2_signatures.v1_rsa[0]);
    assert_zone_file_omits_key(&zone_file, &rot2_signatures.v1_ed25519[0]);

    // Make sure only the new keys are being used for signing
    assert_ne!(
        rot3_signatures.v1_rsa[0].selector, rot4_signatures.v1_rsa[0].selector,
        "Expected a new RSA selector to be generated during rotation"
    );
    assert_ne!(
        rot3_signatures.v1_ed25519[0].selector, rot4_signatures.v1_ed25519[0].selector,
        "Expected a new Ed25519 selector to be generated during rotation"
    );
    test.assert_has_signers(
        "dkim.org",
        &[
            &rot4_signatures.v1_rsa[0].selector,
            &rot4_signatures.v1_ed25519[0].selector,
        ],
    )
    .await;

    // Cleanup
    account
        .registry_destroy_all(ObjectType::DkimSignature)
        .await;
    account
        .registry_destroy(ObjectType::Domain, [domain_id])
        .await
        .assert_destroyed(&[domain_id]);
    account.registry_destroy_all(ObjectType::DnsServer).await;
}

async fn fast_retry_tests(test: &TestServer) {
    let account = test.account("admin@example.org");

    // Retry failed tasks every second
    account
        .registry_update_setting(
            TaskManager {
                max_attempts: 100,
                strategy: TaskRetryStrategy::FixedDelay(TaskRetryStrategyFixed {
                    delay: 1_000u64.into(),
                }),
                total_deadline: 86_400_000u64.into(),
            },
            &[],
        )
        .await;
    account.reload_settings().await;

    failed_publish_test(test).await;
    manual_dns_pending_test(test).await;

    account
        .registry_update_setting(TaskManager::default(), &[])
        .await;
    account.reload_settings().await;
}

async fn failed_publish_test(test: &TestServer) {
    println!("Running DKIM failed publish tests...");
    let account = test.account("admin@example.org");
    DNS_RECORDS.lock().unwrap().clear();
    account.dkim_signatures().await.assert_total(0, 0);

    // Create an in-memory DNS server and a DNS server that refuses connections
    let dns_server_id = account.create_memory_dns_server().await;
    let failing_dns_server_id = account.create_failing_dns_server().await;

    // Create a domain whose initial keys rotate shortly
    let domain_id = account
        .registry_create_object(Domain {
            name: "dkim-retry.org".to_string(),
            certificate_management: CertificateManagement::Manual,
            dkim_management: dkim_management(SHORT_ROTATION_MS),
            dns_management: dns_management(dns_server_id),
            ..Default::default()
        })
        .await;
    let initial = account
        .wait_for_dkim_stages(&[(DkimRotationStage::Active, 2)])
        .await
        .assert_total(1, 1);
    let old_rsa = initial.v1_rsa[0].selector.clone();
    let old_ed = initial.v1_ed25519[0].selector.clone();
    test.assert_has_signers("dkim-retry.org", &[&old_rsa, &old_ed])
        .await;

    // Point the domain at the failing DNS server before the rotation is due, and
    // make the keys created from now on long-lived
    account
        .registry_update_object(
            ObjectType::Domain,
            domain_id,
            json!({
                Property::DnsManagement: dns_management(failing_dns_server_id),
                Property::DkimManagement: dkim_management(LONG_ROTATION_MS),
            }),
        )
        .await;
    assert!(
        initial.v1_rsa[0].next_transition_at.unwrap().timestamp() > now() as i64,
        "Rotation was due before the DNS server could be replaced: {:#?}",
        initial
    );

    // The new keys cannot be published, so they must stay pending while the
    // old keys remain active and keep signing
    let failed = account
        .wait_for_dkim_stages(&[
            (DkimRotationStage::Pending, 2),
            (DkimRotationStage::Active, 2),
        ])
        .await
        .assert_total(2, 2)
        .assert_selector_stage(&old_rsa, DkimRotationStage::Active)
        .assert_selector_stage(&old_ed, DkimRotationStage::Active);
    let new_rsa = failed.v1_rsa[0].selector.clone();
    let new_ed = failed.v1_ed25519[0].selector.clone();
    let failed = failed
        .assert_selector_stage(&new_rsa, DkimRotationStage::Pending)
        .assert_selector_stage(&new_ed, DkimRotationStage::Pending);
    test.assert_has_signers("dkim-retry.org", &[&old_rsa, &old_ed])
        .await;

    // Several retries must neither create duplicate keys nor retire the old ones
    let failure_reason = account.wait_for_dkim_task_attempts(domain_id, 4).await;
    assert!(
        failure_reason.contains("Failed to publish DKIM record"),
        "Unexpected failure reason: {failure_reason}"
    );
    let retried = account.dkim_signatures().await;
    assert_eq!(
        retried, failed,
        "DKIM signatures changed while the DNS server was failing"
    );
    test.assert_has_signers("dkim-retry.org", &[&old_rsa, &old_ed])
        .await;

    // Under manual DNS management the pending keys stay pending next to the
    // active keys, and the task stops retrying
    account
        .registry_update_object(
            ObjectType::Domain,
            domain_id,
            json!({
                Property::DnsManagement: DnsManagement::Manual,
            }),
        )
        .await;
    account.wait_for_no_dkim_tasks(domain_id).await;
    assert_eq!(
        account.dkim_signatures().await,
        failed,
        "DKIM signatures changed under manual DNS management"
    );
    test.assert_has_signers("dkim-retry.org", &[&old_rsa, &old_ed])
        .await;

    // Once automatic DNS management uses a working server again, the pending
    // keys are activated and the old keys start retiring
    account
        .registry_update_object(
            ObjectType::Domain,
            domain_id,
            json!({
                Property::DnsManagement: dns_management(dns_server_id),
            }),
        )
        .await;
    let recovered = account
        .wait_for_dkim_stages(&[
            (DkimRotationStage::Active, 2),
            (DkimRotationStage::Retiring, 2),
        ])
        .await
        .assert_total(2, 2)
        .assert_selector_stage(&new_rsa, DkimRotationStage::Active)
        .assert_selector_stage(&new_ed, DkimRotationStage::Active)
        .assert_selector_stage(&old_rsa, DkimRotationStage::Retiring)
        .assert_selector_stage(&old_ed, DkimRotationStage::Retiring);
    test.assert_has_signers("dkim-retry.org", &[&new_rsa, &new_ed])
        .await;
    let records = DNS_RECORDS.lock().unwrap().clone();
    assert_key_has_dns_record(&records, "dkim-retry.org", &recovered.v1_rsa[0]);
    assert_key_has_dns_record(&records, "dkim-retry.org", &recovered.v1_ed25519[0]);

    // Cleanup
    account.registry_destroy_all(ObjectType::Task).await;
    account
        .registry_destroy_all(ObjectType::DkimSignature)
        .await;
    account
        .registry_destroy(ObjectType::Domain, [domain_id])
        .await
        .assert_destroyed(&[domain_id]);
    account.registry_destroy_all(ObjectType::DnsServer).await;
}

async fn unscheduled_keys_test(
    test: &TestServer,
    domain: &str,
    initial_dns_management: fn(Id) -> DnsManagement,
) {
    println!("Running DKIM unscheduled key tests for {domain}...");
    let account = test.account("admin@example.org");
    DNS_RECORDS.lock().unwrap().clear();
    account.dkim_signatures().await.assert_total(0, 0);
    let dns_server_id = account.create_memory_dns_server().await;

    // Keys created while DKIM records are not published automatically are
    // active, unpublished and have no rotation schedule
    let domain_id = account
        .registry_create_object(Domain {
            name: domain.to_string(),
            certificate_management: CertificateManagement::Manual,
            dkim_management: dkim_management(SHORT_ROTATION_MS),
            dns_management: initial_dns_management(dns_server_id),
            ..Default::default()
        })
        .await;
    let initial = account
        .wait_for_dkim_stages(&[(DkimRotationStage::Active, 2)])
        .await
        .assert_total(1, 1);
    assert!(
        initial.keys().all(|key| key.next_transition_at.is_none()),
        "Unexpected rotation schedule for unpublished keys: {initial:#?}"
    );
    let records = DNS_RECORDS.lock().unwrap().clone();
    assert_key_has_no_dns_record(&records, domain, &initial.v1_rsa[0]);
    assert_key_has_no_dns_record(&records, domain, &initial.v1_ed25519[0]);
    let old_rsa = initial.v1_rsa[0].selector.clone();
    let old_ed = initial.v1_ed25519[0].selector.clone();

    // Publishing DKIM records automatically publishes the keys and schedules
    // their rotation
    account
        .registry_update_object(
            ObjectType::Domain,
            domain_id,
            json!({
                Property::DnsManagement: dns_management(dns_server_id),
            }),
        )
        .await;
    let scheduled = account
        .wait_for_dkim("active keys with a rotation schedule", |signatures| {
            signatures.total() == 2
                && signatures.stage_count(DkimRotationStage::Active) == 2
                && signatures
                    .keys()
                    .all(|key| key.next_transition_at.is_some())
        })
        .await;

    // Make the keys created by the rotation long-lived
    account
        .registry_update_object(
            ObjectType::Domain,
            domain_id,
            json!({
                Property::DkimManagement: dkim_management(LONG_ROTATION_MS),
            }),
        )
        .await;
    assert!(
        scheduled
            .keys()
            .all(|key| key.next_transition_at.unwrap().timestamp() > now() as i64),
        "Rotation was due before the rotation period could be extended: {scheduled:#?}"
    );
    wait_for_dns_records(domain, &[&old_rsa, &old_ed]).await;

    // The keys rotate once the schedule elapses
    let rotated = account
        .wait_for_dkim_stages(&[
            (DkimRotationStage::Active, 2),
            (DkimRotationStage::Retiring, 2),
        ])
        .await
        .assert_total(2, 2)
        .assert_selector_stage(&old_rsa, DkimRotationStage::Retiring)
        .assert_selector_stage(&old_ed, DkimRotationStage::Retiring);
    test.assert_has_signers(
        domain,
        &[&rotated.v1_rsa[0].selector, &rotated.v1_ed25519[0].selector],
    )
    .await;
    let records = DNS_RECORDS.lock().unwrap().clone();
    assert_key_has_dns_record(&records, domain, &rotated.v1_rsa[0]);
    assert_key_has_dns_record(&records, domain, &rotated.v1_ed25519[0]);

    // Cleanup
    account.registry_destroy_all(ObjectType::Task).await;
    account
        .registry_destroy_all(ObjectType::DkimSignature)
        .await;
    account
        .registry_destroy(ObjectType::Domain, [domain_id])
        .await
        .assert_destroyed(&[domain_id]);
    account.registry_destroy_all(ObjectType::DnsServer).await;
}

async fn automatic_to_manual_dns_test(test: &TestServer) {
    println!("Running DKIM automatic to manual DNS tests...");
    let account = test.account("admin@example.org");
    DNS_RECORDS.lock().unwrap().clear();
    account.dkim_signatures().await.assert_total(0, 0);
    let dns_server_id = account.create_memory_dns_server().await;

    // Create a domain whose initial keys rotate shortly
    let domain_id = account
        .registry_create_object(Domain {
            name: "dkim-mirror.org".to_string(),
            certificate_management: CertificateManagement::Manual,
            dkim_management: dkim_management(SHORT_ROTATION_MS),
            dns_management: dns_management(dns_server_id),
            ..Default::default()
        })
        .await;
    let initial = account
        .wait_for_dkim_stages(&[(DkimRotationStage::Active, 2)])
        .await
        .assert_total(1, 1);
    let old_rsa = initial.v1_rsa[0].selector.clone();
    let old_ed = initial.v1_ed25519[0].selector.clone();

    // Switch to manual DNS management before the rotation is due, and make the
    // keys created from now on long-lived
    account
        .registry_update_object(
            ObjectType::Domain,
            domain_id,
            json!({
                Property::DnsManagement: DnsManagement::Manual,
                Property::DkimManagement: dkim_management(LONG_ROTATION_MS),
            }),
        )
        .await;
    let due = initial.v1_rsa[0].next_transition_at.unwrap().timestamp();
    let wait_secs = due - now() as i64;
    assert!(
        wait_secs > 0,
        "Rotation was due before DNS management was switched: {initial:#?}"
    );

    // Once the rotation is due, the task must neither rotate the keys nor keep
    // retrying
    tokio::time::sleep(std::time::Duration::from_secs(wait_secs as u64 + 1)).await;
    account.wait_for_no_dkim_tasks(domain_id).await;
    assert_eq!(
        account.dkim_signatures().await,
        initial,
        "DKIM signatures changed under manual DNS management"
    );
    test.assert_has_signers("dkim-mirror.org", &[&old_rsa, &old_ed])
        .await;

    // Switching back to automatic DNS management completes the overdue rotation
    account
        .registry_update_object(
            ObjectType::Domain,
            domain_id,
            json!({
                Property::DnsManagement: dns_management(dns_server_id),
            }),
        )
        .await;
    let rotated = account
        .wait_for_dkim_stages(&[
            (DkimRotationStage::Active, 2),
            (DkimRotationStage::Retiring, 2),
        ])
        .await
        .assert_total(2, 2)
        .assert_selector_stage(&old_rsa, DkimRotationStage::Retiring)
        .assert_selector_stage(&old_ed, DkimRotationStage::Retiring);
    test.assert_has_signers(
        "dkim-mirror.org",
        &[&rotated.v1_rsa[0].selector, &rotated.v1_ed25519[0].selector],
    )
    .await;
    let records = DNS_RECORDS.lock().unwrap().clone();
    assert_key_has_dns_record(&records, "dkim-mirror.org", &rotated.v1_rsa[0]);
    assert_key_has_dns_record(&records, "dkim-mirror.org", &rotated.v1_ed25519[0]);

    // Cleanup
    account.registry_destroy_all(ObjectType::Task).await;
    account
        .registry_destroy_all(ObjectType::DkimSignature)
        .await;
    account
        .registry_destroy(ObjectType::Domain, [domain_id])
        .await
        .assert_destroyed(&[domain_id]);
    account.registry_destroy_all(ObjectType::DnsServer).await;
}

async fn manual_dns_pending_test(test: &TestServer) {
    println!("Running DKIM pending key under manual DNS tests...");
    let account = test.account("admin@example.org");
    DNS_RECORDS.lock().unwrap().clear();
    account.dkim_signatures().await.assert_total(0, 0);
    let failing_dns_server_id = account.create_failing_dns_server().await;

    // Keys created while the DNS server is failing stay pending
    let domain_id = account
        .registry_create_object(Domain {
            name: "dkim-pending.org".to_string(),
            certificate_management: CertificateManagement::Manual,
            dkim_management: dkim_management(LONG_ROTATION_MS),
            dns_management: dns_management(failing_dns_server_id),
            ..Default::default()
        })
        .await;
    let pending = account
        .wait_for_dkim_stages(&[(DkimRotationStage::Pending, 2)])
        .await
        .assert_total(1, 1);
    let rsa = pending.v1_rsa[0].selector.clone();
    let ed = pending.v1_ed25519[0].selector.clone();

    // Switching to manual DNS management activates the pending keys without a
    // rotation schedule, and the task stops retrying
    account
        .registry_update_object(
            ObjectType::Domain,
            domain_id,
            json!({
                Property::DnsManagement: DnsManagement::Manual,
            }),
        )
        .await;
    let active = account
        .wait_for_dkim_stages(&[(DkimRotationStage::Active, 2)])
        .await
        .assert_total(1, 1)
        .assert_selector_stage(&rsa, DkimRotationStage::Active)
        .assert_selector_stage(&ed, DkimRotationStage::Active);
    assert!(
        active.keys().all(|key| key.next_transition_at.is_none()),
        "Unexpected rotation schedule under manual DNS management: {active:#?}"
    );
    test.assert_has_signers("dkim-pending.org", &[&rsa, &ed])
        .await;
    account.wait_for_no_dkim_tasks(domain_id).await;

    // Cleanup
    account.registry_destroy_all(ObjectType::Task).await;
    account
        .registry_destroy_all(ObjectType::DkimSignature)
        .await;
    account
        .registry_destroy(ObjectType::Domain, [domain_id])
        .await
        .assert_destroyed(&[domain_id]);
    account.registry_destroy_all(ObjectType::DnsServer).await;
}

fn dns_management(dns_server_id: Id) -> DnsManagement {
    DnsManagement::Automatic(DnsManagementProperties {
        dns_server_id,
        publish_records: Map::new(vec![DnsRecordType::Dkim]),
        ..Default::default()
    })
}

fn dkim_management(rotate_after: u64) -> DkimManagement {
    DkimManagement::Automatic(DkimManagementProperties {
        delete_after: Duration::from_millis(LONG_ROTATION_MS),
        retire_after: Duration::from_millis(LONG_ROTATION_MS),
        rotate_after: Duration::from_millis(rotate_after),
        selector_template: "dummy-v{version}-{algorithm}-{epoch}".to_string(),
        ..Default::default()
    })
}

async fn wait_for_dns_records(domain: &str, selectors: &[&str]) {
    for _ in 0..50 {
        let records = DNS_RECORDS.lock().unwrap().clone();
        if selectors
            .iter()
            .all(|selector| has_dns_record(&records, domain, selector))
        {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    panic!(
        "DNS records for selectors {selectors:?} were not published: {:#?}",
        DNS_RECORDS.lock().unwrap()
    );
}

#[derive(Debug, PartialEq, Eq, Default)]
struct DkimSignatures {
    v1_rsa: Vec<Dkim1Signature>,
    v1_ed25519: Vec<Dkim1Signature>,
}

impl Account {
    async fn wait_for_dkim_signatures(
        &self,
        last_signatures: &DkimSignatures,
        expected_total: usize,
    ) -> DkimSignatures {
        let mut signatures = self.dkim_signatures().await;
        for _ in 0..10 {
            if signatures != *last_signatures
                && signatures.v1_rsa.len() + signatures.v1_ed25519.len() == expected_total
            {
                return signatures;
            }
            tokio::time::sleep(std::time::Duration::from_millis(400)).await;
            signatures = self.dkim_signatures().await;
        }
        panic!(
            "DKIM signatures did not change after waiting (total {}, expected {}): {:#?}",
            signatures.v1_rsa.len() + signatures.v1_ed25519.len(),
            expected_total,
            signatures
        );
    }

    async fn wait_for_dkim_stages(
        &self,
        expected: &[(DkimRotationStage, usize)],
    ) -> DkimSignatures {
        let expected_total = expected.iter().map(|(_, count)| count).sum::<usize>();
        self.wait_for_dkim(&format!("stages {expected:?}"), |signatures| {
            signatures.total() == expected_total
                && expected
                    .iter()
                    .all(|(stage, count)| signatures.stage_count(*stage) == *count)
        })
        .await
    }

    async fn wait_for_dkim(
        &self,
        expected: &str,
        is_expected: impl Fn(&DkimSignatures) -> bool,
    ) -> DkimSignatures {
        let mut signatures = self.dkim_signatures().await;
        for _ in 0..50 {
            if is_expected(&signatures) {
                return signatures;
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            signatures = self.dkim_signatures().await;
        }
        panic!("DKIM signatures did not reach {expected}: {signatures:#?}");
    }

    async fn wait_for_no_dkim_tasks(&self, domain_id: Id) {
        for _ in 0..60 {
            if self.tasks().await.is_some_and(|tasks| {
                !tasks.iter().any(|task| {
                    matches!(&task.task, Task::DkimManagement(task) if task.domain_id == domain_id)
                })
            }) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
        panic!(
            "DKIM management task did not complete: {:#?}",
            self.tasks()
                .await
                .map(|tasks| tasks.into_iter().map(|task| task.task).collect::<Vec<_>>())
        );
    }

    async fn create_failing_dns_server(&self) -> Id {
        self.registry_create_object(DnsServer::Tsig(DnsServerTsig {
            host: "127.0.0.1".parse().unwrap(),
            port: 1,
            key_name: "stalwart-update-key".to_string(),
            key: SecretKey::Value(SecretKeyValue {
                secret: "c3RhbHdhcnQtdGVzdC10c2lnLXNlY3JldA==".into(),
            }),
            protocol: IpProtocol::Tcp,
            tsig_algorithm: TsigAlgorithm::HmacSha256,
            description: "Unreachable DNS server".to_string(),
            timeout: Duration::from_millis(1_000),
            ..Default::default()
        }))
        .await
    }

    async fn create_memory_dns_server(&self) -> Id {
        self.registry_create_object(DnsServer::Cloudflare(DnsServerCloudflare {
            secret: SecretKey::Value(SecretKeyValue {
                secret: "test@memory.org".into(),
            }),
            description: "In-memory DNS server".to_string(),
            ..Default::default()
        }))
        .await
    }

    async fn wait_for_dkim_task_attempts(&self, domain_id: Id, attempts: u64) -> String {
        for _ in 0..60 {
            if let Some(tasks) = self.tasks().await
                && let Some(failure_reason) = tasks.into_iter().find_map(|task| match task.task {
                    Task::DkimManagement(TaskDomainManagement {
                        domain_id: task_domain_id,
                        status: TaskStatus::Retry(retry),
                    }) if task_domain_id == domain_id && retry.attempt_number >= attempts => {
                        Some(retry.failure_reason)
                    }
                    _ => None,
                })
            {
                return failure_reason;
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
        panic!(
            "DKIM management task did not reach {attempts} attempts: {:#?}",
            self.tasks()
                .await
                .map(|tasks| tasks.into_iter().map(|task| task.task).collect::<Vec<_>>())
        );
    }

    async fn dkim_signatures(&self) -> DkimSignatures {
        let signatures = self.registry_get_all::<DkimSignature>().await;
        let mut v1_rsa = Vec::new();
        let mut v1_ed25519 = Vec::new();
        for (_, signature) in signatures {
            match signature {
                DkimSignature::Dkim1RsaSha256(sig) => v1_rsa.push(sig),
                DkimSignature::Dkim1Ed25519Sha256(sig) => v1_ed25519.push(sig),
                DkimSignature::Dkim2Ed25519Sha256(_) | DkimSignature::Dkim2RsaSha256(_) => todo!(),
            }
        }

        // Sort in descending order of creation time
        v1_rsa.sort_by_key(|s| std::cmp::Reverse(s.created_at));
        v1_ed25519.sort_by_key(|s| std::cmp::Reverse(s.created_at));

        DkimSignatures { v1_rsa, v1_ed25519 }
    }
}

impl DkimSignatures {
    fn keys(&self) -> impl Iterator<Item = &Dkim1Signature> {
        self.v1_rsa.iter().chain(&self.v1_ed25519)
    }

    fn total(&self) -> usize {
        self.v1_rsa.len() + self.v1_ed25519.len()
    }

    fn stage_count(&self, stage: DkimRotationStage) -> usize {
        self.v1_rsa.iter().filter(|s| s.stage == stage).count()
            + self.v1_ed25519.iter().filter(|s| s.stage == stage).count()
    }

    fn assert_selector_stage(self, selector: &str, stage: DkimRotationStage) -> Self {
        assert!(
            self.v1_rsa
                .iter()
                .chain(self.v1_ed25519.iter())
                .any(|s| s.selector == selector && s.stage == stage),
            "Expected selector {} in stage {:?}: {:#?}",
            selector,
            stage,
            self
        );
        self
    }

    fn assert_stage_count(self, stage: DkimRotationStage, count: usize) -> Self {
        let actual_count = self.stage_count(stage);
        assert_eq!(
            actual_count, count,
            "Expected {} signatures in stage {:?}, found {}: {:#?}",
            count, stage, actual_count, self
        );
        self
    }

    fn assert_total(self, total_rsa: usize, total_ed25519: usize) -> Self {
        assert_eq!(
            self.v1_rsa.len(),
            total_rsa,
            "Expected {} RSA signatures, found {:?}",
            total_rsa,
            self.v1_rsa
        );
        assert_eq!(
            self.v1_ed25519.len(),
            total_ed25519,
            "Expected {} Ed25519 signatures, found {:?}",
            total_ed25519,
            self.v1_ed25519
        );
        self
    }

    fn assert_selector_missing(self, selector: &str) -> Self {
        assert!(
            !self.v1_rsa.iter().any(|s| s.selector == selector)
                && !self.v1_ed25519.iter().any(|s| s.selector == selector),
            "Selector {} was unexpectedly found in signatures: {:#?}",
            selector,
            self
        );
        self
    }
}

impl TestServer {
    async fn published_dkim_records(&self, domain_id: Id) -> (Vec<NamedDnsRecord>, String) {
        let domain = self
            .server
            .registry()
            .object::<Domain>(domain_id)
            .await
            .unwrap()
            .expect("Domain not found");
        let records = self
            .server
            .build_dns_records(domain_id, &domain, &[DnsRecordType::Dkim])
            .await
            .unwrap();
        let zone_file = self
            .server
            .build_bind_dns_records(domain_id, &domain)
            .await
            .unwrap();

        (records, zone_file)
    }

    async fn assert_has_signers(&self, domain: &str, selectors: &[&str]) {
        assert_eq!(
            self.server
                .dkim_signers(domain)
                .await
                .unwrap()
                .unwrap_or_else(|| panic!("No signatures found: {:?}", selectors))
                .dkim1
                .iter()
                .map(|s| match s {
                    Dkim1Signer::RsaSha256(s) => s.template.s.as_str(),
                    Dkim1Signer::Ed25519Sha256(s) => s.template.s.as_str(),
                })
                .collect::<AHashSet<_>>(),
            selectors.iter().copied().collect::<AHashSet<_>>()
        );
    }
}

fn has_dns_record(records: &[NamedDnsRecord], domain: &str, selector: &str) -> bool {
    let expected = format!("{selector}._domainkey.{domain}.");
    records.iter().any(|record| {
        record.name == expected
            && matches!(&record.record, DnsRecord::TXT(txt)
                if (selector.contains("rsa") && txt.starts_with("v=DKIM1; k=rsa; h=sha256; p="))
                    || (selector.contains("ed25519")
                        && txt.starts_with("v=DKIM1; k=ed25519; h=sha256; p=")))
    })
}

fn assert_key_has_dns_record(records: &[NamedDnsRecord], domain: &str, key: &Dkim1Signature) {
    assert!(
        has_dns_record(records, domain, &key.selector),
        "No DNS record found for DKIM key with selector {}, records: {:#?}",
        key.selector,
        records
    );
}

fn assert_zone_file_omits_key(zone_file: &str, key: &Dkim1Signature) {
    assert!(
        !zone_file.contains(&key.selector),
        "Unexpected zone file entry for DKIM key with selector {}, zone file: {}",
        key.selector,
        zone_file
    );
}

fn assert_key_has_no_dns_record(records: &[NamedDnsRecord], domain: &str, key: &Dkim1Signature) {
    assert!(
        !has_dns_record(records, domain, &key.selector),
        "Unexpected DNS record found for DKIM key with selector {}, records: {:#?}",
        key.selector,
        records
    );
}
