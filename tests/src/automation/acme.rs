/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::server::TestServer;
use ahash::AHashSet;
use common::network::dns::update::DNS_RECORDS;
use dns_update::DnsRecord;
use jmap_proto::error::set::SetErrorType;
use registry::{
    schema::{
        enums::{AcmeChallengeType, AcmeRenewBefore, DnsRecordType},
        prelude::{ObjectType, Property},
        structs::{
            AcmeProvider, Action, Certificate, CertificateManagement,
            CertificateManagementProperties, DkimManagement, DnsManagement,
            DnsManagementProperties, DnsServer, DnsServerCloudflare, Domain, PublicText,
            PublicTextValue, SecretKey, SecretKeyValue, SecretText, SecretTextValue, Task,
            TaskDomainManagement,
        },
    },
    types::{datetime::UTCDateTime, id::ObjectId, map::Map},
};
use serde_json::json;
use store::{registry::write::RegistryWrite, write::now};
use x509_parser::parse_x509_certificate;
use x509_parser::pem::Pem;

pub async fn test(test: &TestServer) {
    println!("Running ACME tests...");
    let account = test.account("admin@example.org");

    // Manually insert certificates with different expiration dates
    let now = now() as i64;
    test.server
        .registry()
        .write(RegistryWrite::insert(
            &Certificate {
                certificate: PublicText::Text(PublicTextValue {
                    value: ISSUER_ABC_CERT.to_string(),
                }),
                private_key: SecretText::Text(SecretTextValue {
                    secret: ISSUER_ABC_PK.to_string(),
                }),
                issuer: "Issuer ABC".to_string(),
                not_valid_after: UTCDateTime::from_timestamp(now + 86400),
                not_valid_before: UTCDateTime::from_timestamp(now - 10),
                subject_alternative_names: Map::new(vec!["mail.example.org".to_string()]),
            }
            .into(),
        ))
        .await
        .unwrap();
    test.server
        .registry()
        .write(RegistryWrite::insert(
            &Certificate {
                certificate: PublicText::Text(PublicTextValue {
                    value: ISSUER_XYZ_CERT.to_string(),
                }),
                private_key: SecretText::Text(SecretTextValue {
                    secret: ISSUER_XYZ_PK.to_string(),
                }),
                issuer: "Issuer XYZ".to_string(),
                not_valid_after: UTCDateTime::from_timestamp(now + (2 * 86400)),
                not_valid_before: UTCDateTime::from_timestamp(now - 10),
                subject_alternative_names: Map::new(vec!["mail.example.org".to_string()]),
            }
            .into(),
        ))
        .await
        .unwrap();
    test.server
        .registry()
        .write(RegistryWrite::insert(
            &Certificate {
                certificate: PublicText::Text(PublicTextValue {
                    value: ISSUER_123_CERT.to_string(),
                }),
                private_key: SecretText::Text(SecretTextValue {
                    secret: ISSUER_123_PK.to_string(),
                }),
                issuer: "Issuer 123".to_string(),
                not_valid_after: UTCDateTime::from_timestamp(now - 86400),
                not_valid_before: UTCDateTime::from_timestamp(now - 100),
                subject_alternative_names: Map::new(vec!["mail.example.org".to_string()]),
            }
            .into(),
        ))
        .await
        .unwrap();
    assert_eq!(
        account
            .registry_get_all::<Certificate>()
            .await
            .into_iter()
            .map(|(_, c)| c.issuer)
            .collect::<AHashSet<_>>(),
        AHashSet::from_iter(vec![
            "Issuer ABC".to_string(),
            "Issuer XYZ".to_string(),
            "Issuer 123".to_string()
        ])
    );

    // Reload certificates and make XYZ is used for mail.example.org
    account
        .registry_create_object(Action::ReloadTlsCertificates)
        .await;
    assert_eq!(
        parse_x509_certificate(
            test.server
                .resolve_certificate("mail.example.org")
                .unwrap()
                .end_entity_cert()
                .unwrap()
        )
        .unwrap()
        .1
        .tbs_certificate
        .issuer
        .to_string(),
        "CN=Issuer XYZ CA"
    );

    // Make sure the expired certificate was deleted
    assert_eq!(
        account
            .registry_get_all::<Certificate>()
            .await
            .into_iter()
            .map(|(_, c)| c.issuer)
            .collect::<AHashSet<_>>(),
        AHashSet::from_iter(vec!["Issuer ABC".to_string(), "Issuer XYZ".to_string()])
    );
    account.registry_destroy_all(ObjectType::Certificate).await;

    // Create test Pebble and In Memory DNS servers
    let pebble_dns_id = account
        .registry_create_object(DnsServer::Cloudflare(DnsServerCloudflare {
            secret: SecretKey::Value(SecretKeyValue {
                secret: "test@pebble.org".into(),
            }),
            description: "Pebble DNS server".to_string(),
            ..Default::default()
        }))
        .await;
    let in_memory_dns_id = account
        .registry_create_object(DnsServer::Cloudflare(DnsServerCloudflare {
            secret: SecretKey::Value(SecretKeyValue {
                secret: "test@memory.org".into(),
            }),
            description: "In-memory DNS server".to_string(),
            ..Default::default()
        }))
        .await;

    // ACME provider creation should fail without a contact email
    account
        .registry_create_object_expect_err(AcmeProvider {
            directory: "https://localhost:14000/dir".to_string(),
            ..Default::default()
        })
        .await
        .assert_type(SetErrorType::InvalidProperties)
        .assert_description_contains("At least one contact email is required");

    // Create an ACME provider using TLS-ALPN-01 challenge
    let tls_acme_id = account
        .registry_create_object(AcmeProvider {
            directory: "https://localhost:14000/dir".to_string(),
            contact: Map::new(vec!["mailto:hello@tls.org".to_string()]),
            challenge_type: AcmeChallengeType::TlsAlpn01,
            renew_before: AcmeRenewBefore::R12,
            ..Default::default()
        })
        .await;
    let provider = account.registry_get::<AcmeProvider>(tls_acme_id).await;
    assert_eq!(provider.directory, "https://localhost:14000/dir");
    assert_eq!(
        provider.contact,
        Map::new(vec!["mailto:hello@tls.org".to_string()])
    );
    assert!(
        provider.account_uri.starts_with("https://localhost:14000"),
        "Provider {:?} has invalid account URI",
        provider
    );

    // Create a domain and trigger TLS-ALPN-01 ACME renewal
    let tls_domain_id = account
        .registry_create_object(Domain {
            name: "tls.org".to_string(),
            certificate_management: CertificateManagement::Automatic(
                CertificateManagementProperties {
                    acme_provider_id: tls_acme_id,
                    subject_alternative_names: Default::default(),
                },
            ),
            dkim_management: DkimManagement::Manual,
            dns_management: DnsManagement::Automatic(DnsManagementProperties {
                dns_server_id: in_memory_dns_id,
                publish_records: Map::new(vec![
                    DnsRecordType::Tlsa,
                    DnsRecordType::AutoConfig,
                    DnsRecordType::AutoConfigLegacy,
                    DnsRecordType::AutoDiscover,
                    DnsRecordType::MtaSts,
                ]),
                ..Default::default()
            }),
            ..Default::default()
        })
        .await;
    test.wait_for_tasks_skip_not_due().await;
    let certificate = account
        .registry_get_all::<Certificate>()
        .await
        .into_iter()
        .next()
        .unwrap()
        .1;
    let mut sans = certificate.subject_alternative_names.into_inner();
    sans.sort();
    assert_eq!(
        sans,
        vec![
            "autoconfig.tls.org".to_string(),
            "autodiscover.tls.org".to_string(),
            "mta-sts.tls.org".to_string(),
            "ua-auto-config.tls.org".to_string()
        ]
    );

    // Make sure the TLSA records were added to the in-memory DNS server
    let records = DNS_RECORDS.lock().unwrap().clone();
    for record in [
        "_443._tcp.mta-sts.tls.org.",
        "_443._tcp.autoconfig.tls.org.",
        "_443._tcp.ua-auto-config.tls.org.",
        "_443._tcp.autodiscover.tls.org.",
    ] {
        if records
            .iter()
            .find(|r| r.name == record && matches!(r.record, DnsRecord::TLSA(_)))
            .is_none()
        {
            panic!(
                "Expected TLSA record for {} not found in DNS records: {:?}",
                record, records
            );
        }
    }

    // Make sure a task was created to renew the certificate before it expires
    let tasks = account.registry_get_all::<Task>().await;
    assert_eq!(
        tasks.len(),
        1,
        "Expected 1 task, found {}: {:?}",
        tasks.len(),
        tasks
    );
    let task = tasks.into_iter().next().unwrap().1;
    if let Task::AcmeRenewal(TaskDomainManagement {
        domain_id: task_domain_id,
        ..
    }) = task
    {
        assert_eq!(
            task_domain_id, tls_domain_id,
            "ACME renewal task has incorrect domain ID"
        );
    } else {
        panic!("Expected ACME renewal task, found: {:?}", task);
    }
    let not_valid_after = certificate.not_valid_after.timestamp();
    let not_valid_before = certificate.not_valid_before.timestamp();
    let length = not_valid_after - not_valid_before;
    assert_eq!(
        not_valid_before + length / 2,
        task.due_timestamp() as i64,
        "ACME renewal task has incorrect due timestamp, expected around {} but found {}",
        not_valid_before + length / 2,
        task.due_timestamp() as i64
    );
    account.registry_destroy_all(ObjectType::Certificate).await;
    account.registry_destroy_all(ObjectType::Task).await;

    // Test ACME using HTTP-01 challenge and the server domain "mail.example.org"
    let http_acme_id = account
        .registry_create_object(AcmeProvider {
            directory: "https://localhost:14000/dir".to_string(),
            contact: Map::new(vec!["mailto:hello@example.org".to_string()]),
            challenge_type: AcmeChallengeType::Http01,
            ..Default::default()
        })
        .await;
    let domain_id = account.find_or_create_domain("example.org").await;
    account.registry_update_object(ObjectType::Domain, domain_id, json!({
        Property::CertificateManagement: CertificateManagement::Automatic(CertificateManagementProperties {
            acme_provider_id: http_acme_id,
            subject_alternative_names: Default::default(),
        }),
    })).await;
    test.wait_for_tasks_skip_not_due().await;
    let certificate = account
        .registry_get_all::<Certificate>()
        .await
        .into_iter()
        .next()
        .unwrap()
        .1;
    let mut sans = certificate.subject_alternative_names.into_inner();
    sans.sort();
    assert_eq!(
        sans,
        vec![
            "autoconfig.example.org".to_string(),
            "autodiscover.example.org".to_string(),
            "imap.example.org".to_string(),
            "mail.example.org".to_string(),
            "mta-sts.example.org".to_string(),
            "mx1.example.org".to_string(),
            "mx2.example.org".to_string(),
            "pop3.example.org".to_string(),
            "smtp.example.org".to_string(),
            "ua-auto-config.example.org".to_string()
        ]
    );
    account.registry_destroy_all(ObjectType::Certificate).await;
    account.registry_destroy_all(ObjectType::Task).await;

    // Test ACME using DNS-01 challenge
    let dns_acme_id = account
        .registry_create_object(AcmeProvider {
            directory: "https://localhost:14000/dir".to_string(),
            contact: Map::new(vec!["mailto:hello@dns.org".to_string()]),
            challenge_type: AcmeChallengeType::Dns01,
            ..Default::default()
        })
        .await;
    let dns_domain_id = account
        .registry_create_object(Domain {
            name: "dns.org".to_string(),
            certificate_management: CertificateManagement::Automatic(
                CertificateManagementProperties {
                    acme_provider_id: dns_acme_id,
                    subject_alternative_names: Default::default(),
                },
            ),
            dkim_management: DkimManagement::Manual,
            dns_management: DnsManagement::Automatic(DnsManagementProperties {
                dns_server_id: pebble_dns_id,
                publish_records: Map::new(vec![DnsRecordType::Caa]),
                ..Default::default()
            }),
            ..Default::default()
        })
        .await;
    test.wait_for_tasks_skip_not_due().await;
    let certificate = account
        .registry_get_all::<Certificate>()
        .await
        .into_iter()
        .next()
        .unwrap()
        .1;
    let mut sans = certificate.subject_alternative_names.into_inner();
    sans.sort();
    assert_eq!(sans, vec!["*.dns.org".to_string(), "dns.org".to_string()]);
    account.registry_destroy_all(ObjectType::Certificate).await;
    account.registry_destroy_all(ObjectType::Task).await;

    // Test ACME using DNS-01 challenge
    let dns_acme_id = account
        .registry_create_object(AcmeProvider {
            directory: "https://localhost:14000/dir".to_string(),
            contact: Map::new(vec!["mailto:hello@persist.org".to_string()]),
            challenge_type: AcmeChallengeType::DnsPersist01,
            ..Default::default()
        })
        .await;
    let persist_domain_id = account
        .registry_create_object(Domain {
            name: "persist.org".to_string(),
            certificate_management: CertificateManagement::Automatic(
                CertificateManagementProperties {
                    acme_provider_id: dns_acme_id,
                    subject_alternative_names: Default::default(),
                },
            ),
            dkim_management: DkimManagement::Manual,
            dns_management: DnsManagement::Automatic(DnsManagementProperties {
                dns_server_id: pebble_dns_id,
                publish_records: Map::new(vec![DnsRecordType::Caa]),
                ..Default::default()
            }),
            ..Default::default()
        })
        .await;
    test.wait_for_tasks_skip_not_due().await;
    let certificate = account
        .registry_get_all::<Certificate>()
        .await
        .into_iter()
        .next()
        .unwrap()
        .1;
    let mut sans = certificate.subject_alternative_names.into_inner();
    sans.sort();
    assert_eq!(
        sans,
        vec!["*.persist.org".to_string(), "persist.org".to_string()]
    );

    // Test preferred chain selection against the alternate chains Pebble offers (RFC 8555 7.4.2)
    let pebble_roots = pebble_root_common_names().await;
    assert!(
        pebble_roots.len() >= 2,
        "Expected Pebble to offer multiple root chains, found: {:?}",
        pebble_roots
    );

    // Renew without a preferred chain to discover the default root
    let default_acme_id = account
        .registry_create_object(AcmeProvider {
            directory: "https://localhost:14000/dir".to_string(),
            contact: Map::new(vec!["mailto:hello@chain.org".to_string()]),
            challenge_type: AcmeChallengeType::TlsAlpn01,
            ..Default::default()
        })
        .await;
    let default_domain_id = account
        .registry_create_object(Domain {
            name: "chain.org".to_string(),
            certificate_management: CertificateManagement::Automatic(
                CertificateManagementProperties {
                    acme_provider_id: default_acme_id,
                    subject_alternative_names: Default::default(),
                },
            ),
            dkim_management: DkimManagement::Manual,
            dns_management: DnsManagement::Automatic(DnsManagementProperties {
                dns_server_id: in_memory_dns_id,
                ..Default::default()
            }),
            ..Default::default()
        })
        .await;
    test.wait_for_tasks_skip_not_due().await;
    let default_chain = account
        .registry_get_all::<Certificate>()
        .await
        .into_iter()
        .next()
        .unwrap()
        .1
        .certificate
        .value()
        .await
        .unwrap()
        .into_owned();
    let default_root = top_issuer_common_name(&default_chain)
        .expect("default chain should expose a top issuer common name");
    assert!(
        pebble_roots.contains(&default_root),
        "Default root {:?} not among Pebble roots {:?}",
        default_root,
        pebble_roots
    );
    account.registry_destroy_all(ObjectType::Certificate).await;
    account.registry_destroy_all(ObjectType::Task).await;

    // Renew with a preferred chain pointing at an alternate root and verify it is honored
    let preferred_root = pebble_roots
        .iter()
        .find(|cn| **cn != default_root)
        .cloned()
        .expect("an alternate root distinct from the default");
    let preferred_acme_id = account
        .registry_create_object(AcmeProvider {
            directory: "https://localhost:14000/dir".to_string(),
            contact: Map::new(vec!["mailto:hello@chainalt.org".to_string()]),
            challenge_type: AcmeChallengeType::TlsAlpn01,
            preferred_chain: Some(preferred_root.clone()),
            ..Default::default()
        })
        .await;
    let preferred_domain_id = account
        .registry_create_object(Domain {
            name: "chainalt.org".to_string(),
            certificate_management: CertificateManagement::Automatic(
                CertificateManagementProperties {
                    acme_provider_id: preferred_acme_id,
                    subject_alternative_names: Default::default(),
                },
            ),
            dkim_management: DkimManagement::Manual,
            dns_management: DnsManagement::Automatic(DnsManagementProperties {
                dns_server_id: in_memory_dns_id,
                ..Default::default()
            }),
            ..Default::default()
        })
        .await;
    test.wait_for_tasks_skip_not_due().await;
    let preferred_chain = account
        .registry_get_all::<Certificate>()
        .await
        .into_iter()
        .next()
        .unwrap()
        .1
        .certificate
        .value()
        .await
        .unwrap()
        .into_owned();
    let selected_root = top_issuer_common_name(&preferred_chain)
        .expect("preferred chain should expose a top issuer common name");
    assert_eq!(
        selected_root, preferred_root,
        "ACME did not select the preferred certificate chain"
    );
    assert_ne!(
        selected_root, default_root,
        "Preferred chain matches the default; selection was not exercised"
    );
    account
        .registry_destroy(ObjectType::Domain, [default_domain_id, preferred_domain_id])
        .await
        .assert_destroyed(&[default_domain_id, preferred_domain_id]);
    account.registry_destroy_all(ObjectType::Certificate).await;
    account.registry_destroy_all(ObjectType::Task).await;
    account.registry_destroy_all(ObjectType::AcmeProvider).await;

    // reuse_key: the keypair (and thus the SPKI published in DANE "3 1 1" records) must
    // stay stable across renewals when enabled, and rotate when disabled.
    for (reuse_key, expect_stable) in [(true, true), (false, false)] {
        account.registry_destroy_all(ObjectType::Certificate).await;
        account.registry_destroy_all(ObjectType::Task).await;

        let reuse_acme_id = account
            .registry_create_object(AcmeProvider {
                directory: "https://localhost:14000/dir".to_string(),
                contact: Map::new(vec!["mailto:hello@reuse.org".to_string()]),
                challenge_type: AcmeChallengeType::TlsAlpn01,
                reuse_key,
                ..Default::default()
            })
            .await;
        let reuse_domain_id = account
            .registry_create_object(Domain {
                name: "reuse.org".to_string(),
                certificate_management: CertificateManagement::Automatic(
                    CertificateManagementProperties {
                        acme_provider_id: reuse_acme_id,
                        subject_alternative_names: Default::default(),
                    },
                ),
                dkim_management: DkimManagement::Manual,
                dns_management: DnsManagement::Automatic(DnsManagementProperties {
                    dns_server_id: in_memory_dns_id,
                    ..Default::default()
                }),
                ..Default::default()
            })
            .await;

        // Initial issuance
        test.wait_for_tasks_skip_not_due().await;
        let (first_id, first_cert) = account
            .registry_get_all::<Certificate>()
            .await
            .into_iter()
            .next()
            .expect("a certificate to be issued");
        let first_chain = first_cert.certificate.value().await.unwrap().into_owned();
        let first_key = leaf_public_key(&first_chain);

        // Backdate the stored certificate so a renewal is immediately due, then renew it.
        // The reuse path must locate this certificate by its SANs and reuse its private key.
        let reference = store::write::now() as i64;
        let object_id = ObjectId::new(ObjectType::Certificate, first_id);
        let old = test
            .server
            .registry()
            .get(object_id)
            .await
            .unwrap()
            .expect("stored certificate");
        let mut backdated = Certificate::from(old.clone());
        backdated.not_valid_before = UTCDateTime::from_timestamp(reference - 1_000_000);
        backdated.not_valid_after = UTCDateTime::from_timestamp(reference - 10);
        test.server
            .registry()
            .write(RegistryWrite::update(first_id, &backdated.into(), &old))
            .await
            .unwrap();
        test.server
            .acme_renew(reuse_domain_id)
            .await
            .ok()
            .expect("certificate renewal to succeed");

        let (_, renewed_cert) = account
            .registry_get_all::<Certificate>()
            .await
            .into_iter()
            .find(|(id, _)| *id != first_id)
            .expect("a renewed certificate");
        let renewed_chain = renewed_cert.certificate.value().await.unwrap().into_owned();
        let second_key = leaf_public_key(&renewed_chain);

        if expect_stable {
            assert_eq!(
                first_key, second_key,
                "reuse_key=true must preserve the certificate public key across renewals"
            );
        } else {
            assert_ne!(
                first_key, second_key,
                "reuse_key=false must rotate the certificate public key on renewal"
            );
        }

        account
            .registry_destroy(ObjectType::Domain, [reuse_domain_id])
            .await
            .assert_destroyed(&[reuse_domain_id]);
        account.registry_destroy_all(ObjectType::Certificate).await;
        account.registry_destroy_all(ObjectType::Task).await;
        account.registry_destroy_all(ObjectType::AcmeProvider).await;
    }

    // Cleanup
    account
        .registry_update_object(
            ObjectType::Domain,
            domain_id,
            json!({
                Property::CertificateManagement: CertificateManagement::Manual,
            }),
        )
        .await;
    account
        .registry_destroy(
            ObjectType::Domain,
            [tls_domain_id, dns_domain_id, persist_domain_id],
        )
        .await
        .assert_destroyed(&[tls_domain_id, dns_domain_id, persist_domain_id]);
    account.registry_destroy_all(ObjectType::DnsServer).await;
    account.registry_destroy_all(ObjectType::AcmeProvider).await;
    account.registry_destroy_all(ObjectType::Certificate).await;
    account.registry_destroy_all(ObjectType::Task).await;
}

const ISSUER_ABC_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIIDLjCCAhagAwIBAgIURV4DMcpCSV95vODPEDWtzZ0XTjIwDQYJKoZIhvcNAQEL
BQAwGDEWMBQGA1UEAwwNSXNzdWVyIEFCQyBDQTAeFw0yNjA0MDMxMjQ1MjVaFw0y
NzA0MDMxMjQ1MjVaMBgxFjAUBgNVBAMMDUlzc3VlciBBQkMgQ0EwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQC+iuw9/2hAtmt/1+K26N/XNuWRaUvJFfqs
cV5ZXzcRywXvamHivbL7OcVf96D9y67vh+beYReYo4N+ObtWJRA+5+SeBjmfEdDf
sgLn5lABvzQmFUDBIbGLN9xjYSLYcfTpN0Edla/mRJf70fxzniTFUbrtnEZ4G19Y
oDVb9V9hyTG35ak+mm20boIJkgbTW4G1xD/Q3eaWKXeKNLDxBI3wBWg1xGpMB58l
z3IiHRUtzzE5V5jtSy0oQ4+VR0u9WJdYhPqxMNzixuzEeMveB2Xd+Mf4FuvQy+wg
xU2Sb1ZqnK14+vGNAbA7mHIBvAfUMZSuYnCIGvr37XpjMBc7nm+JAgMBAAGjcDBu
MB0GA1UdDgQWBBRW3foBUlBYWVKpuJTo175EYhv7mDAfBgNVHSMEGDAWgBRW3foB
UlBYWVKpuJTo175EYhv7mDAPBgNVHRMBAf8EBTADAQH/MBsGA1UdEQQUMBKCEG1h
aWwuZXhhbXBsZS5vcmcwDQYJKoZIhvcNAQELBQADggEBAANV8NOesHrSbqtqkrXW
nIfriEr5a7mVW8FIsyhDxMTOeRjkM+8nFFsjNvTe3HDvF8zDGPmCMKuxQHQ+8NAA
CKjcQEkv5PBb8gMRRQUexSPJF1hrqFA/cQn+lVnv6eZ2r/K7NlM80otvZIRtJbWi
1hlwE2EBEq9tWgrPUEjStlYzO5rAmxM2/yprbzYMiL0g4d8VIseVaQl9C/M00VLU
r9fw/Rz43kBGcDE5T7Gb2T8pUmZhhZykADglgU8MrPp6VD2oOTF5Qxl6CMd/bG+B
YyEBkY27+hfdf68rIrjOJJ518/gYKGVVHP3FDWPlus4hURn+g85CKu4p3a3TPbl3
VWw=
-----END CERTIFICATE-----
"#;

const ISSUER_ABC_PK: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC+iuw9/2hAtmt/
1+K26N/XNuWRaUvJFfqscV5ZXzcRywXvamHivbL7OcVf96D9y67vh+beYReYo4N+
ObtWJRA+5+SeBjmfEdDfsgLn5lABvzQmFUDBIbGLN9xjYSLYcfTpN0Edla/mRJf7
0fxzniTFUbrtnEZ4G19YoDVb9V9hyTG35ak+mm20boIJkgbTW4G1xD/Q3eaWKXeK
NLDxBI3wBWg1xGpMB58lz3IiHRUtzzE5V5jtSy0oQ4+VR0u9WJdYhPqxMNzixuzE
eMveB2Xd+Mf4FuvQy+wgxU2Sb1ZqnK14+vGNAbA7mHIBvAfUMZSuYnCIGvr37Xpj
MBc7nm+JAgMBAAECggEAAOWJGddxOuWVbbPB+T+6NsgU9Ry/1zmT7lzgEJrP6yKN
QqJC15YgAgW0dwdkmd5HdxDfr2xHCkFNS2yDn44wBaILOBy3vntqllAITxxohAtN
io3oQzT3fU5UBeoftWOIv1JXWSL4SuS1hjyVVRIXMEbxSX4GKLl1G3Ae/LrmCffu
IFpQdidxY/ZpCXLqWLK3ysmA1Sq0BmJeIB3EwsrwJn/OK6nJC8N35bTpOx5ZVnUL
CZGQFmUZRpSFs+wAWy0f0mGrMOWVjN0nUZUj52ZZoyZ1sxc7DLxDGoqO72Mia+/3
xtAOwq4kkonCEVRNGDOOOiVOSufz6dGv4dJ2WYCvJQKBgQD8XtHu/Ro6QOPDb2k8
ovHnlCAe0cFk8kNlQhsKVJ5ybDWUJPOxjfgv8LudUSExdMtryus9KkGHqJ5pMLzC
x/Y3492pQpYY303lSo4crUWt/W6BUhWIfeA2827eQRTbccz00Evy9NugK8RCUJTO
Ek1BKUVWkugFEria5XETFNiZ5QKBgQDBSHb9q1SGIDE9yQLdEZ2FjWYvrcKqa792
lwxw/QAzDBNXZbsN2PAkYbyDltbtOOvDBrHmGWR2EECAW5ifo5rhmakgKfshzMDj
w2piXz1QhzFuPolozp10iE7GpKH/s0NI5RA8CFLMKy9wsbTw8VmyqtOg6XZ3yhXX
+6MQodaU1QKBgQCF0MlEDZSgmtOqRyLn8gaOom49qT8AhazSvjCUU7YIOfRW7xkA
ZqTY1q7EhcYx8RoDt/7v2b4RbolAgYU1Ss31aK+aFiJ8Ybtt/xBHiGDQFvdHPv0H
+KawvHdnBd9HVJo2nVQIKWljDpHsD8o3UmEAUh/f/dllBz43c713PrBzOQKBgQCG
wLnM0zVDqZALDmiDrfNPmCxlE1TDsgkzac3PvGP2MvYNGazW06dhBg8DAxfnHacp
OjKvRIbI1T3S/4khy1OA87t45Cvk/baBVM2HtfSufwLUZJ8yRdJ620loroEPH3DK
koDGCduH4pfZjtuim/G4YebXqczhaS/fe93NC7fp3QKBgQCu+Mw7NPuNI8og453k
jsxBVlh52xvw9Y26OTFfuwBB05iDOLK6Qh+VpQEhI26uSESgwjy0m+VEev4uQYPD
5kPQpyO84CcbIsdfsJysbA48sn5Wzg1MGYJUc97eKu70cUs3yXQsuU6cs3M4C2Sf
j+UnghyPLhlHVTL/Xw60mZc+xw==
-----END PRIVATE KEY-----
"#;

const ISSUER_XYZ_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIIDLjCCAhagAwIBAgIUGDz02vh30maG1BceejuWOSUO6ZQwDQYJKoZIhvcNAQEL
BQAwGDEWMBQGA1UEAwwNSXNzdWVyIFhZWiBDQTAeFw0yNjA0MDMxMjQ3MzRaFw0y
NzA0MDMxMjQ3MzRaMBgxFjAUBgNVBAMMDUlzc3VlciBYWVogQ0EwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDBUPhu/4n3ZMRUGLToU/0iUbXk6e7yJTvv
RJrrn5FFGrulxGcdZaKdmh5ZBiQu15xjXz7IZBmkXiyUy/4LMznvAC8OBeSut1pZ
f8D3Jox7PRAMPuTfUh9C9qBMFhDj+pXOd/fHy4JgJ22rDQQsCLV8N0JAkBEEvRnF
GDeriSWIReUbluRVblgR2jeVXwkvGeiNcrlbE3+zAPKX4JXmLJYgfFwjjZyvCo7L
P/tqLdR31bxpjtrpY3VjbpsqMh3qiLhsfzxBwy3vQCBzQ77thjUU77Ixrhp0dkY1
DonTDuIxvvMNLZkX+EgonuGgtNwolWoOb4FNKJINdYW8JtknVnT/AgMBAAGjcDBu
MB0GA1UdDgQWBBTOZ3eOed6PrLVb0iysnnGcEm0ylzAfBgNVHSMEGDAWgBTOZ3eO
ed6PrLVb0iysnnGcEm0ylzAPBgNVHRMBAf8EBTADAQH/MBsGA1UdEQQUMBKCEG1h
aWwuZXhhbXBsZS5vcmcwDQYJKoZIhvcNAQELBQADggEBAI9aZDT21yXxl67sDHSj
IGGAqhcpfNQdqCAvNbYdeiXTHZE7SHndF2efMRj1iJ9lAsYalFi0jbNCoU/KVDv8
V7ApxhNlxl5kHmtKBJJLxXyklX+Fic10nUQY5EqU351Rn6Lapp2jn5DmXxlrsy+x
CSYVSU8l3ag3Wzdnl2rua6PlLYiFJIKsmqyUBNhvuXVsRkf+y2BVLglOTc3cXdBh
iCgOds4SjP8DCBmFqeBIKrcuzXeWU7WQL6XruuQyV3QGghEw3YxQpbbsbDtHFgZx
kKO1vQmsym1pUFXV2Drg03FA1oxXCBiRJMbNWSsFZhllKlPpbkV4+IqTMd3u9+JN
Fhk=
-----END CERTIFICATE-----
"#;

const ISSUER_XYZ_PK: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDBUPhu/4n3ZMRU
GLToU/0iUbXk6e7yJTvvRJrrn5FFGrulxGcdZaKdmh5ZBiQu15xjXz7IZBmkXiyU
y/4LMznvAC8OBeSut1pZf8D3Jox7PRAMPuTfUh9C9qBMFhDj+pXOd/fHy4JgJ22r
DQQsCLV8N0JAkBEEvRnFGDeriSWIReUbluRVblgR2jeVXwkvGeiNcrlbE3+zAPKX
4JXmLJYgfFwjjZyvCo7LP/tqLdR31bxpjtrpY3VjbpsqMh3qiLhsfzxBwy3vQCBz
Q77thjUU77Ixrhp0dkY1DonTDuIxvvMNLZkX+EgonuGgtNwolWoOb4FNKJINdYW8
JtknVnT/AgMBAAECggEAI06ICTHHv3TafKeEhvgr/9Qfnf7xwqz1PNZxWv5qOE5R
Hk34LUDOSe2HhGfgPOPpLqcLHutVWZVPnB+DtwT0nEeS0INYCGb5a+Yu1pTmTG3T
HAFyqKzlg8Pqc+sFy7WNHcgAa6+qEKiy2W5HqEkw6E5pXcRSL2TgK4SoSj6CqdgU
2O44I1FD4+zQNJHWKnKGAHr4ZyTdqLOCogWPH0cNHmF3o8sXDDnuRNn94BN/9EE+
QHEkbxqVoOUmuVSqyj2FNThQmyth4LMTQbGOqBisokHyDdfCxXrXa2IRVtWGNZKb
u73LCTqjUqiV1I/oYnoSL3qDFIX9fQt8CaZc8kKZzQKBgQDmHJk747QUyOs0hSjg
qYz2OfR7RsrX0N/hgi2AaUPyqD1pagCEWAJioB/RY42nsAqW4n27z/BLntUTgKzY
xLO9Rcu+xAk5QOYiTnOSHyqtcYHDYfTdqj8QlJBD5L3whsWLs5u40wSCamEnEEP/
yQXvpRYFsOisZ6FxA4EkDz9d0wKBgQDXEKJftDPeap1qRatQpk1BT5GvuGWDEtt/
AZHSr9x4nvStzt6pEw01naP2AnJyh+z4mUqdP9ycNsWePL6/OFNfbBfQGfa3m1QE
DT94FmUYjVsKdaR/6PgAE/n0FRLYCxgsju56lMG2oxdm+lu7Hi3h9X+2TCP26Cm3
Kyt5hBuUpQKBgCWSs96YjpX6PJWFzKfqZ27pBad/Zq2YmIXM6LsX9RVRLT3iJhV1
/WW3OZrKA55G22PJtbgN+vGODMKzdwWqEKMuG1eZ0Nu9YhZl8u8AEcriRsrtWrs7
CjMd3vSHDBCTIPxvplSmeA0Ha7eiK0g/va1kqlThjwxfm3fFl7eYmcMrAoGAU2Q7
0ehKBIBKsZ56IzeY1S5JS12w3vY87i5poMxYLN1V+t8wL1cX1CZgIVApmIdkN7EY
4YiVvmzui8D6JaNtkJ6VTTgEFoXAOiH47lOgt7h4CMI9Guv23fDhBuf0+piysvRp
PFbaFjt/I4sIbrHxEKDk+IblmyPCqSewH9o955ECgYEAyX4UO6jcBCrSVGiMBnBm
RU1EcAdWxAwu4LRvhxJFBGBMHI36ECrMmPmbVvyzTfGSQfLo8Ov2z0T3Ec2jR86V
0Wu4jn4vxDVj4OD+oGScc3JuaVQJ5Mj7KP2HdXw9Z7pQ9LQYCzmwLoWOq3iYDrsJ
RcWUqLOFB3faKiFxfcjnOrU=
-----END PRIVATE KEY-----
"#;

const ISSUER_123_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIIDLjCCAhagAwIBAgIUKcxy6IK4xfMTqdlbvTi8zvDgaz0wDQYJKoZIhvcNAQEL
BQAwGDEWMBQGA1UEAwwNSXNzdWVyIDEyMyBDQTAeFw0yNjA0MDMxMjQ4MDZaFw0y
NzA0MDMxMjQ4MDZaMBgxFjAUBgNVBAMMDUlzc3VlciAxMjMgQ0EwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCnXWNMF4m8e2VPVlM8DWuaZPaBx1vqWQCG
1MjInefh5FIAtimCl43cRd7Iolb8k+qdWm5xfWaOsh6fDVJqF9DLXweVOk58tYMr
Dg2buT7W5SfUS1fcg+rdv/0IRQc9LV9l4sLsW9L1Lv/2nltDnEVwypOxyFLHQdhb
SdCxQky8oPWkb6BQlK4Tths0iwY+4vQDpzv8WRY0h0nlLN54OQcCeOtUUjkEu6L5
6goUM8SVlH1aQmBPXEIaUXKa36IevRirLAXw7d6BLijWwMJU2EXvrl+xVgomf0Md
pRRLaPjLS5vPnoJ7ZbQOA3AMKoIwwXE50xckirINUBXK7jocwXBzAgMBAAGjcDBu
MB0GA1UdDgQWBBRKWPP6BQ3xNVaJ6Rjjy5E27bUW9TAfBgNVHSMEGDAWgBRKWPP6
BQ3xNVaJ6Rjjy5E27bUW9TAPBgNVHRMBAf8EBTADAQH/MBsGA1UdEQQUMBKCEG1h
aWwuZXhhbXBsZS5vcmcwDQYJKoZIhvcNAQELBQADggEBAI6UqptJYfQ5bWn3SAU1
sT2GTaOlQDPHI08v3fAGomzL5COsx9WgdgBuO3yjcNPXrlyTCdpXLVgQDeIbfoHf
B2FLSBXgtkDFCwTX5P+D4odif7zt8Fr0Zbgo7NEi+TJvQRron3bvbY78JUOujIj2
MNJRntcl1cp7aZSNaNhCogFxY5t01fqJuaW//QdfApvOXB6mWjONGo5p01jkK2HA
AoiHdZMGGnTdb2Usx6ZkENwgwKHY3TMXMQvUysH5STUrw4/eBfNLnCZgK8GRK8nC
kqPwO96ZdZ9EmzOMxUCCVrFyXwThnNu7aHbWKDq1KQsRvHMWjCwn0gxoqZixoA8K
gpg=
-----END CERTIFICATE-----
"#;

const ISSUER_123_PK: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCnXWNMF4m8e2VP
VlM8DWuaZPaBx1vqWQCG1MjInefh5FIAtimCl43cRd7Iolb8k+qdWm5xfWaOsh6f
DVJqF9DLXweVOk58tYMrDg2buT7W5SfUS1fcg+rdv/0IRQc9LV9l4sLsW9L1Lv/2
nltDnEVwypOxyFLHQdhbSdCxQky8oPWkb6BQlK4Tths0iwY+4vQDpzv8WRY0h0nl
LN54OQcCeOtUUjkEu6L56goUM8SVlH1aQmBPXEIaUXKa36IevRirLAXw7d6BLijW
wMJU2EXvrl+xVgomf0MdpRRLaPjLS5vPnoJ7ZbQOA3AMKoIwwXE50xckirINUBXK
7jocwXBzAgMBAAECggEAEre5jr2FLHy6cFyNs4Ymth47iXkj2Po6Oloa2ID8eYGB
AE5fJxlPBscTqumpA9eBIjcGag/lw+i8zvn88RuXwN7waKqcM4tTT6HjOLrHgd4g
Dbida26fekxp/p5FuHxWEn2BYlDEr6Ihg1HjkBSumXY2fWgThfBhw5fmTKTHE0NY
c2Q57UOw94lkPCPrmP25wEh+4DwUNIuV3wKQq9t8Qq5XkOlFd9V4957mz9qLH4G3
oXUU/yQToEKPbA62WqAUbE26nnJ03Xr+r2+waDR+VfaNtAWKdoQAtgI7Ge02obHZ
jO5T8/pFVchJxNjKKRp2hdPYn6y7JZOAsXqEt5eawQKBgQDr6ps/AW4WyK6o2g/t
NstPtXkBSLrwesrpg7AiEUh3eqximjtOF7ksvJ1kqhkzTvVfB2/h8EO8eJ4SsxLD
VsHUTduWXyASeh392RuMsvHigfTi3//lsaYSSRBEsruZAXjqjWtAh5Ap76F2BpcB
wQNCb1D6NyILshMyepXnEGNbswKBgQC1nND2rSLYfpY4X3hUiI+yNMef6b1AlJAg
X4Qd4xVetrPrTO4Fn8UVgUFQiDdZMsDjbg7idyh975UIq5kp1AikfRfAXilCw+uT
ZBvu2xjScls2fScu4Vn1wBky/n83NLx8zi0CepN2qYvjPpNYIlJ2Ych+SWCoXxeT
fPCZzqg4QQKBgQCKdecn028JcD8SWul+D+rDnX6ngkg1W9w7sU5usDYX6afDN0IX
U1UbLJgzvKGNu4nHfFXuBVW8CA6+attYSlL4h7mZR7tLHOD9W68PpPbSOfPANDe8
V8dgdAFYUI5J/tM41kdcWDQEaOAapUN7hAylsS+Vq0YQFzOtLMVOGBA4gQKBgQCj
COjqWVkrws/2QXZTZNii4RDH9NwpanTMKxL+hYn8ocV4mXIf6GLTwFozAmW1lINm
Z7nDAbd+/qHqy6lOzIMJryawUZd20Uzc3wTYcyWgXnqVutp/Elxg6hd1GNR5acU/
wRLU49cXsnLbCKTbfMxMa9HB1PuJivwuMf4IBWYsQQKBgQC5KNAWEHWrnxiNeCS0
4VzOCTCUEQ+Axq7g5bFKzJqRfHDXlDsNaiK6q4vGDp4HjFawPoyrmnR5/OE/O8PV
0OstcrM2EBik9YbORVpAJ2yl90ZTKevSxQ9+n2Ip/pwLz/oRywxF/dYYTbwYReO5
9MBumBf1lgiJZSsloOKWQvLchg==
-----END PRIVATE KEY-----
"#;

async fn pebble_root_common_names() -> Vec<String> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("Failed to build HTTP client");
    let mut common_names = Vec::new();
    for index in 0.. {
        let response = client
            .get(format!("https://localhost:15000/roots/{index}"))
            .send()
            .await
            .expect("Failed to query Pebble management API");
        if !response.status().is_success() {
            break;
        }
        let pem = response.text().await.expect("Failed to read Pebble root");
        match subject_common_name(&pem) {
            Some(common_name) => common_names.push(common_name),
            None => break,
        }
    }
    common_names
}

fn subject_common_name(pem: &str) -> Option<String> {
    let block = Pem::iter_from_buffer(pem.as_bytes()).next()?.ok()?;
    let cert = block.parse_x509().ok()?;
    cert.subject()
        .iter_common_name()
        .filter_map(|cn| cn.as_str().ok())
        .next()
        .map(str::to_string)
}

fn leaf_public_key(chain: &str) -> Vec<u8> {
    let block = Pem::iter_from_buffer(chain.as_bytes())
        .next()
        .expect("certificate chain should contain a leaf")
        .expect("valid PEM block");
    let cert = block.parse_x509().expect("valid leaf certificate");
    cert.public_key().raw.to_vec()
}

fn top_issuer_common_name(chain: &str) -> Option<String> {
    let block = Pem::iter_from_buffer(chain.as_bytes())
        .filter_map(Result::ok)
        .last()?;
    let cert = block.parse_x509().ok()?;
    cert.issuer()
        .iter_common_name()
        .filter_map(|cn| cn.as_str().ok())
        .next()
        .map(str::to_string)
}
