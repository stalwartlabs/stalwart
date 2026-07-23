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
        enums::DkimRotationStage,
        prelude::ObjectType,
        structs::{
            CertificateManagement, Dkim1Signature, DkimManagement, DkimManagementProperties,
            DkimSignature, DnsManagement, DnsManagementProperties, DnsServer, DnsServerCloudflare,
            Domain, SecretKey, SecretKeyValue,
        },
    },
    types::duration::Duration,
};
use store::write::now;

pub async fn test(test: &TestServer) {
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
    assert_key_has_dns_record(&records, &rot1_signatures.v1_rsa[0]);
    assert_key_has_dns_record(&records, &rot1_signatures.v1_ed25519[0]);

    // Expect a rotation to happen and new keys to be created
    let rot2_signatures = account
        .wait_for_dkim_signatures(&rot1_signatures, 4)
        .await
        .assert_total(2, 2)
        .assert_stage_count(DkimRotationStage::Active, 2)
        .assert_stage_count(DkimRotationStage::Retiring, 2);

    // Make sure both old and new keys have DNS records
    let records = DNS_RECORDS.lock().unwrap().clone();
    assert_key_has_dns_record(&records, &rot1_signatures.v1_rsa[0]);
    assert_key_has_dns_record(&records, &rot1_signatures.v1_ed25519[0]);
    assert_key_has_dns_record(&records, &rot2_signatures.v1_rsa[0]);
    assert_key_has_dns_record(&records, &rot2_signatures.v1_ed25519[0]);

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
    assert_key_has_no_dns_record(&records, &rot1_signatures.v1_rsa[0]);
    assert_key_has_no_dns_record(&records, &rot1_signatures.v1_ed25519[0]);
    assert_key_has_dns_record(&records, &rot2_signatures.v1_rsa[0]);
    assert_key_has_dns_record(&records, &rot2_signatures.v1_ed25519[0]);
    assert_key_has_dns_record(&records, &rot3_signatures.v1_rsa[0]);
    assert_key_has_dns_record(&records, &rot3_signatures.v1_ed25519[0]);

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
    assert_key_has_dns_record(&records, &rot4_signatures.v1_rsa[0]);
    assert_key_has_dns_record(&records, &rot4_signatures.v1_ed25519[0]);
    assert_key_has_no_dns_record(&records, &rot2_signatures.v1_rsa[0]);
    assert_key_has_no_dns_record(&records, &rot2_signatures.v1_ed25519[0]);

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
    fn assert_stage_count(self, stage: DkimRotationStage, count: usize) -> Self {
        let actual_count = self.v1_rsa.iter().filter(|s| s.stage == stage).count()
            + self.v1_ed25519.iter().filter(|s| s.stage == stage).count();
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

fn assert_key_has_dns_record(records: &[NamedDnsRecord], key: &Dkim1Signature) {
    let expected = format!("{}._domainkey.dkim.org.", key.selector);
    for record in records {
        if record.name == expected
            && let DnsRecord::TXT(txt) = &record.record
            && ((key.selector.contains("rsa") && txt.starts_with("v=DKIM1; k=rsa; h=sha256; p="))
                || (key.selector.contains("ed25519")
                    && txt.starts_with("v=DKIM1; k=ed25519; h=sha256; p=")))
        {
            return;
        }
    }
    panic!(
        "No DNS record found for DKIM key with selector {}, records: {:#?}",
        key.selector, records
    );
}

fn assert_key_has_no_dns_record(records: &[NamedDnsRecord], key: &Dkim1Signature) {
    let expected = format!("{}._domainkey.dkim.org.", key.selector);
    for record in records {
        if record.name == expected
            && let DnsRecord::TXT(txt) = &record.record
            && ((key.selector.contains("rsa") && txt.starts_with("v=DKIM1; k=rsa; h=sha256; p="))
                || (key.selector.contains("ed25519")
                    && txt.starts_with("v=DKIM1; k=ed25519; h=sha256; p=")))
        {
            panic!(
                "Unexpected DNS record found for DKIM key with selector {}, records: {:#?}",
                key.selector, records
            );
        }
    }
}
