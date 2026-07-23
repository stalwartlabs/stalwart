/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    smtp::{
        inbound::{TestMessage, TestQueueEvent, TestReportingEvent},
        session::{TestSession, VerifyResponse},
    },
    utils::{dns::DnsCache, server::TestServerBuilder},
};
use common::{
    config::smtp::resolver::{Tlsa, TlsaEntry, TlsaMatching},
    ipc::PolicyType,
};
use mail_auth::{
    DnssecStatus, MX,
    common::parse::TxtRecordParser,
    mta_sts::{ReportUri, TlsRpt},
    report::tlsrpt::ResultType,
};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PublicKeyData, date_time_ymd,
};
use registry::schema::{
    enums::MtaRequiredOrOptional,
    prelude::ObjectType,
    structs::{Expression, MtaTlsStrategy, TlsReportSettings},
};
use rustls_pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use smtp::outbound::dane::{
    dnssec::{TlsaLookup, TlsaResult},
    verify::TlsaVerify,
};
use smtp::queue::{Error, ErrorDetails, Status};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{BufRead, BufReader},
    num::ParseIntError,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use store::write::now;

#[tokio::test]
#[serial_test::serial]
async fn dane_verify() {
    let mut local = TestServerBuilder::new("smtp_dane_verify_local")
        .await
        .with_http_listener(19018)
        .await
        .disable_services()
        .capture_queue()
        .capture_reporting()
        .build()
        .await;
    let mut remote = TestServerBuilder::new("smtp_dane_verify_remote")
        .await
        .with_dummy_tls_cert(["*.foobar.org"])
        .await
        .with_http_listener(19019)
        .await
        .with_smtp_listener(9925)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;

    let local_admin = local.account("admin");
    local_admin.mta_allow_relaying().await;
    local_admin.mta_no_auth().await;
    local_admin
        .registry_create_object(TlsReportSettings {
            send_frequency: Expression {
                else_: "weekly".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    let (tls_strategy_id, mut tls_strategy) = local_admin
        .registry_get_all::<MtaTlsStrategy>()
        .await
        .into_iter()
        .find(|(_, s)| s.name == "default")
        .unwrap();
    tls_strategy.dane = MtaRequiredOrOptional::Require;
    tls_strategy.start_tls = MtaRequiredOrOptional::Require;
    let mut tls_strategy = serde_json::to_value(tls_strategy).unwrap();
    tls_strategy
        .as_object_mut()
        .unwrap()
        .retain(|k, _| k != "name");
    local_admin
        .registry_update_object(ObjectType::MtaTlsStrategy, tls_strategy_id, tls_strategy)
        .await;
    local_admin.reload_settings().await;
    local.reload_core();
    local.expect_reload_settings().await;

    let remote_admin = remote.account("admin");
    remote_admin.mta_no_auth().await;
    remote_admin.mta_allow_relaying().await;
    remote_admin.mta_add_all_headers().await;
    remote_admin.mta_allow_non_fqdn().await;
    remote_admin.reload_settings().await;
    remote.reload_core();
    remote.expect_reload_settings().await;

    // Add mock DNS entries
    local.server.mx_add(
        "foobar.org",
        vec![MX {
            exchanges: vec!["mx.foobar.org".into()].into_boxed_slice(),
            preference: 10,
        }],
        DnssecStatus::Secure,
        Instant::now() + Duration::from_secs(10),
    );
    local.server.ipv4_add(
        "mx.foobar.org",
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(10),
    );
    local.server.txt_add(
        "_smtp._tls.foobar.org",
        TlsRpt::parse(b"v=TLSRPTv1; rua=mailto:reports@foobar.org").unwrap(),
        Instant::now() + Duration::from_secs(10),
    );

    let mut session = local.new_mta_session();
    session.data.remote_ip_str = "10.0.0.1".into();
    session.eval_session_params().await;
    session.ehlo("mx.test.org").await;
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
        .await;
    local
        .expect_message_then_deliver()
        .await
        .try_deliver(local.server.clone());
    local
        .expect_message()
        .await
        .read_lines(&local)
        .await
        .assert_contains("<bill@foobar.org> (DANE failed to authenticate")
        .assert_contains("No TLSA reco=")
        .assert_contains("rds found");
    local.read_event().await.assert_done();
    local.assert_no_events();

    // Expect TLS failure report
    let report = local.read_report().await.unwrap_tls();
    assert_eq!(report.domain, "foobar.org");
    assert_eq!(report.policy, PolicyType::Tlsa(None));
    assert_eq!(
        report.failure.as_ref().unwrap().result_type,
        ResultType::DaneRequired
    );
    assert_eq!(
        report.failure.as_ref().unwrap().receiving_mx_hostname,
        Some("mx.foobar.org".to_string())
    );
    assert_eq!(
        report.tls_record.rua,
        vec![ReportUri::Mail("reports@foobar.org".to_string())]
    );

    // DANE failure with no matching certificates
    let tlsa = Arc::new(Tlsa {
        entries: vec![TlsaEntry {
            is_end_entity: true,
            is_spki: true,
            matching: TlsaMatching::Sha256,
            data: vec![1, 2, 3],
        }],
        has_end_entities: true,
        has_intermediates: false,
    });
    local.server.tlsa_add(
        "_25._tcp.mx.foobar.org",
        tlsa.clone(),
        Instant::now() + Duration::from_secs(10),
    );
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
        .await;
    local
        .expect_message_then_deliver()
        .await
        .try_deliver(local.server.clone());
    local
        .expect_message()
        .await
        .read_lines(&local)
        .await
        .assert_contains("<bill@foobar.org> (DANE failed to authenticate")
        .assert_contains("No matching ")
        .assert_contains("certificates found");
    local.read_event().await.assert_done();
    local.assert_no_events();

    // Expect TLS failure report
    let report = local.read_report().await.unwrap_tls();
    assert_eq!(report.policy, PolicyType::Tlsa(tlsa.into()));
    assert_eq!(
        report.failure.as_ref().unwrap().result_type,
        ResultType::ValidationFailure
    );
    remote.assert_no_events();

    // DANE successful delivery
    let tlsa = Arc::new(Tlsa {
        entries: vec![TlsaEntry {
            is_end_entity: true,
            is_spki: true,
            matching: TlsaMatching::Sha256,
            data: vec![
                73, 186, 44, 106, 13, 198, 100, 180, 0, 44, 158, 188, 15, 195, 39, 198, 61, 254,
                215, 237, 100, 26, 15, 155, 219, 235, 120, 64, 128, 172, 17, 0,
            ],
        }],
        has_end_entities: true,
        has_intermediates: false,
    });
    local.server.tlsa_add(
        "_25._tcp.mx.foobar.org",
        tlsa.clone(),
        Instant::now() + Duration::from_secs(10),
    );
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
        .await;
    local
        .expect_message_then_deliver()
        .await
        .try_deliver(local.server.clone());
    local.read_event().await.assert_done();
    local.assert_no_events();
    remote
        .expect_message()
        .await
        .read_lines(&remote)
        .await
        .assert_contains("using TLSv1.3 with cipher");

    // Expect TLS success report
    let report = local.read_report().await.unwrap_tls();
    assert_eq!(report.policy, PolicyType::Tlsa(tlsa.into()));
    assert!(report.failure.is_none());

    // An insecure (non-DNSSEC) MX zone must not honor TLSA records,
    // even when valid records are cached.
    local.server.mx_add(
        "foobar.org",
        vec![MX {
            exchanges: vec!["mx.foobar.org".into()].into_boxed_slice(),
            preference: 10,
        }],
        DnssecStatus::Insecure,
        Instant::now() + Duration::from_secs(10),
    );
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
        .await;
    local
        .expect_message_then_deliver()
        .await
        .try_deliver(local.server.clone());
    local
        .expect_message()
        .await
        .read_lines(&local)
        .await
        .assert_contains("<bill@foobar.org> (DANE failed to authenticate");
    local.read_event().await.assert_done();
    local.assert_no_events();
    let report = local.read_report().await.unwrap_tls();
    assert_eq!(report.policy, PolicyType::Tlsa(None));
    assert_eq!(
        report.failure.as_ref().unwrap().result_type,
        ResultType::DaneRequired
    );
    remote.assert_no_events();
}

#[tokio::test]
#[serial_test::serial]
async fn dane_downgrade_on_tlsa_servfail() {
    let mut local = TestServerBuilder::new("smtp_dane_downgrade_local")
        .await
        .with_http_listener(19020)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;
    let mut remote = TestServerBuilder::new("smtp_dane_downgrade_remote")
        .await
        .with_dummy_tls_cert(["*.foobar.org"])
        .await
        .with_http_listener(19021)
        .await
        .with_smtp_listener(9925)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;

    let local_admin = local.account("admin");
    local_admin.mta_allow_relaying().await;
    local_admin.mta_no_auth().await;
    let (tls_strategy_id, mut tls_strategy) = local_admin
        .registry_get_all::<MtaTlsStrategy>()
        .await
        .into_iter()
        .find(|(_, s)| s.name == "default")
        .unwrap();
    tls_strategy.dane = MtaRequiredOrOptional::Optional;
    tls_strategy.start_tls = MtaRequiredOrOptional::Require;
    tls_strategy.allow_invalid_certs = true;
    let mut tls_strategy = serde_json::to_value(tls_strategy).unwrap();
    tls_strategy
        .as_object_mut()
        .unwrap()
        .retain(|k, _| k != "name");
    local_admin
        .registry_update_object(ObjectType::MtaTlsStrategy, tls_strategy_id, tls_strategy)
        .await;
    local_admin.reload_settings().await;
    local.reload_core();
    local.expect_reload_settings().await;

    let remote_admin = remote.account("admin");
    remote_admin.mta_no_auth().await;
    remote_admin.mta_allow_relaying().await;
    remote_admin.mta_add_all_headers().await;
    remote_admin.mta_allow_non_fqdn().await;
    remote_admin.reload_settings().await;
    remote.reload_core();
    remote.expect_reload_settings().await;

    local.server.mx_add(
        "foobar.org",
        vec![MX {
            exchanges: vec!["mx._dns_error.foobar.org".into()].into_boxed_slice(),
            preference: 10,
        }],
        DnssecStatus::Secure,
        Instant::now() + Duration::from_secs(10),
    );
    local.server.ipv4_add(
        "mx._dns_error.foobar.org",
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(10),
    );

    let mut session = local.new_mta_session();
    session.data.remote_ip_str = "10.0.0.1".into();
    session.eval_session_params().await;
    session.ehlo("mx.test.org").await;
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
        .await;
    local
        .expect_message_then_deliver()
        .await
        .try_deliver(local.server.clone());

    let retry = local.expect_message().await;
    assert!(retry.message.recipients[0].retry.due > now());
    remote.assert_no_events();
}

#[tokio::test]
#[serial_test::serial]
async fn dane_bogus_dnssec_temp_fails() {
    let mut local = TestServerBuilder::new("smtp_dane_bogus_local")
        .await
        .with_http_listener(19022)
        .await
        .disable_services()
        .capture_queue()
        .capture_reporting()
        .build()
        .await;

    let local_admin = local.account("admin");
    local_admin.mta_allow_relaying().await;
    local_admin.mta_no_auth().await;
    local_admin
        .registry_create_object(TlsReportSettings {
            send_frequency: Expression {
                else_: "weekly".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    let (tls_strategy_id, mut tls_strategy) = local_admin
        .registry_get_all::<MtaTlsStrategy>()
        .await
        .into_iter()
        .find(|(_, s)| s.name == "default")
        .unwrap();
    tls_strategy.dane = MtaRequiredOrOptional::Require;
    tls_strategy.start_tls = MtaRequiredOrOptional::Require;
    let mut tls_strategy = serde_json::to_value(tls_strategy).unwrap();
    tls_strategy
        .as_object_mut()
        .unwrap()
        .retain(|k, _| k != "name");
    local_admin
        .registry_update_object(ObjectType::MtaTlsStrategy, tls_strategy_id, tls_strategy)
        .await;
    local_admin.reload_settings().await;
    local.reload_core();
    local.expect_reload_settings().await;

    local.server.txt_add(
        "_smtp._tls.foobar.org",
        TlsRpt::parse(b"v=TLSRPTv1; rua=mailto:reports@foobar.org").unwrap(),
        Instant::now() + Duration::from_secs(30),
    );
    local.server.ipv4_add(
        "mx.foobar.org",
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(30),
    );
    local.server.ipv4_add(
        "mx._dnssec_bogus.foobar.org",
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(30),
    );

    let mut session = local.new_mta_session();
    session.data.remote_ip_str = "10.0.0.1".into();
    session.eval_session_params().await;
    session.ehlo("mx.test.org").await;

    local.server.mx_add(
        "foobar.org",
        vec![MX {
            exchanges: vec!["mx.foobar.org".into()].into_boxed_slice(),
            preference: 10,
        }],
        DnssecStatus::Bogus,
        Instant::now() + Duration::from_secs(30),
    );
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
        .await;
    local
        .expect_message_then_deliver()
        .await
        .try_deliver(local.server.clone());
    let retry = local.expect_message().await;
    assert!(retry.message.recipients[0].retry.due > now());

    let report = local.read_report().await.unwrap_tls();
    assert_eq!(report.domain, "foobar.org");
    assert_eq!(report.policy, PolicyType::Tlsa(None));
    assert_eq!(
        report.failure.as_ref().unwrap().result_type,
        ResultType::DnssecInvalid
    );
    assert_eq!(
        report.failure.as_ref().unwrap().receiving_mx_hostname,
        Some("mx.foobar.org".to_string())
    );

    local.server.mx_add(
        "foobar.org",
        vec![MX {
            exchanges: vec!["mx._dnssec_bogus.foobar.org".into()].into_boxed_slice(),
            preference: 10,
        }],
        DnssecStatus::Secure,
        Instant::now() + Duration::from_secs(30),
    );
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
        .await;
    local
        .expect_message_then_deliver()
        .await
        .try_deliver(local.server.clone());
    let retry = local.expect_message().await;
    assert!(retry.message.recipients[0].retry.due > now());

    let report = local.read_report().await.unwrap_tls();
    assert_eq!(report.domain, "foobar.org");
    assert_eq!(report.policy, PolicyType::Tlsa(None));
    assert_eq!(
        report.failure.as_ref().unwrap().result_type,
        ResultType::DnssecInvalid
    );
    assert_eq!(
        report.failure.as_ref().unwrap().receiving_mx_hostname,
        Some("mx._dnssec_bogus.foobar.org".to_string())
    );
}

#[tokio::test]
#[serial_test::serial]
async fn dane_test() {
    let test = TestServerBuilder::new("smtp_dane_remote")
        .await
        .with_http_listener(19036)
        .await
        .disable_services()
        .build()
        .await;

    // Add dns entries
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("resources");
    path.push("smtp");
    path.push("dane");
    let mut file = path.clone();
    file.push("dns.txt");

    let mut hosts = BTreeSet::new();
    let mut tlsa = Tlsa {
        entries: Vec::new(),
        has_end_entities: false,
        has_intermediates: false,
    };
    let mut hostname = String::new();

    for line in BufReader::new(File::open(file).unwrap()).lines() {
        let line = line.unwrap();
        let mut is_end_entity = false;
        for (pos, item) in line.split_whitespace().enumerate() {
            match pos {
                0 => {
                    if hostname != item && !hostname.is_empty() {
                        test.server.tlsa_add(
                            hostname,
                            tlsa.into(),
                            Instant::now() + Duration::from_secs(30),
                        );
                        tlsa = Tlsa {
                            entries: Vec::new(),
                            has_end_entities: false,
                            has_intermediates: false,
                        };
                    }
                    hosts.insert(item.strip_prefix("_25._tcp.").unwrap().to_string());
                    hostname = item.to_string();
                }
                1 => {
                    is_end_entity = item == "3";
                }
                4 => {
                    if is_end_entity {
                        tlsa.has_end_entities = true;
                    } else {
                        tlsa.has_intermediates = true;
                    }
                    tlsa.entries.push(TlsaEntry {
                        is_end_entity,
                        is_spki: true,
                        matching: TlsaMatching::Sha256,
                        data: decode_hex(item).unwrap(),
                    });
                }
                _ => (),
            }
        }
    }
    test.server.tlsa_add(
        hostname,
        tlsa.into(),
        Instant::now() + Duration::from_secs(30),
    );

    // Add certificates
    assert!(!hosts.is_empty());
    for host in hosts {
        // Add certificates
        let mut certs = Vec::new();
        for num in 0..6 {
            let mut file = path.clone();
            file.push(format!("{host}.{num}.cert"));
            if file.exists() {
                certs.push(CertificateDer::from(fs::read(file).unwrap()));
            } else {
                break;
            }
        }

        // Successful DANE verification (end-entity match, RFC 7671 Section 5.1)
        let tlsa = match test
            .server
            .tlsa_lookup(format!("_25._tcp.{host}."))
            .await
            .unwrap()
        {
            TlsaResult::Secure(tlsa) => tlsa,
            _ => panic!("expected secure TLSA records"),
        };

        assert_eq!(
            tlsa.verify(0, &host, &[host.as_str()], Some(&certs)),
            Ok(())
        );

        // Failed DANE verification
        certs.remove(0);
        assert_eq!(
            tlsa.verify(0, &host, &[host.as_str()], Some(&certs)),
            Err(Status::PermanentFailure(ErrorDetails {
                entity: host.into(),
                details: Error::DaneError("No matching certificates found in TLSA records".into())
            }))
        );
    }
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

struct TestCa {
    issuer: Issuer<'static, KeyPair>,
    der: CertificateDer<'static>,
    spki: Vec<u8>,
}

#[test]
fn dane_ee_matches_leaf_ignoring_name() {
    let root = root_ca("EE Root");
    let intermediate = sub_ca("EE Intermediate", &root);
    let (leaf_der, leaf_spki) = leaf_cert("mx.foobar.org", &intermediate);
    let chain = vec![leaf_der, intermediate.der.clone()];

    let record = tlsa(vec![ee_spki_sha256(&leaf_spki)]);
    assert!(
        record
            .verify(0, "mx.foobar.org", &["name.mismatch.example"], Some(&chain))
            .is_ok()
    );

    let wrong = tlsa(vec![ee_spki_sha256(&root.spki)]);
    assert!(
        wrong
            .verify(0, "mx.foobar.org", &["mx.foobar.org"], Some(&chain))
            .is_err()
    );
}

#[test]
fn dane_ee_ignores_expiration() {
    let root = root_ca("Expired EE Root");
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec!["mx.foobar.org".to_string()]).unwrap();
    params.not_before = date_time_ymd(2018, 1, 1);
    params.not_after = date_time_ymd(2021, 1, 1);
    params
        .distinguished_name
        .push(DnType::CommonName, "mx.foobar.org");
    let leaf = params.signed_by(&key, &root.issuer).unwrap();
    let leaf_spki = key.subject_public_key_info();
    let chain = vec![leaf.der().clone()];

    let record = tlsa(vec![ee_spki_sha256(&leaf_spki)]);
    assert!(
        record
            .verify(0, "mx.foobar.org", &["mx.foobar.org"], Some(&chain))
            .is_ok()
    );
}

#[test]
fn dane_ta_anchors_at_private_intermediate() {
    let root = root_ca("TA Private Root");
    let intermediate = sub_ca("TA Intermediate", &root);
    let (leaf_der, _) = leaf_cert("mx.foobar.org", &intermediate);
    let chain = vec![leaf_der, intermediate.der.clone(), root.der.clone()];

    let record = tlsa(vec![ta_full_sha256(&intermediate.der)]);
    assert!(
        record
            .verify(0, "mx.foobar.org", &["mx.foobar.org"], Some(&chain))
            .is_ok()
    );
}

#[test]
fn dane_ta_matches_when_ee_present_but_unmatched() {
    let root = root_ca("Mixed Root");
    let intermediate = sub_ca("Mixed Intermediate", &root);
    let (leaf_der, _) = leaf_cert("mx.foobar.org", &intermediate);
    let chain = vec![leaf_der, intermediate.der.clone(), root.der.clone()];

    let record = tlsa(vec![
        ee_spki_sha256(&root.spki),
        ta_full_sha256(&intermediate.der),
    ]);
    assert!(
        record
            .verify(0, "mx.foobar.org", &["mx.foobar.org"], Some(&chain))
            .is_ok()
    );
}

#[test]
fn dane_ta_requires_name_match() {
    let root = root_ca("Name Root");
    let intermediate = sub_ca("Name Intermediate", &root);
    let (leaf_der, _) = leaf_cert("mx.foobar.org", &intermediate);
    let chain = vec![leaf_der, intermediate.der.clone(), root.der.clone()];

    let record = tlsa(vec![ta_full_sha256(&intermediate.der)]);
    assert!(
        record
            .verify(0, "mx.foobar.org", &["other.example"], Some(&chain))
            .is_err()
    );
    assert!(
        record
            .verify(
                0,
                "mx.foobar.org",
                &["other.example", "mx.foobar.org"],
                Some(&chain)
            )
            .is_ok()
    );
}

#[test]
fn dane_ta_rejects_unrelated_ca_matching_hash() {
    let root = root_ca("Forgery Root");
    let intermediate = sub_ca("Forgery Intermediate", &root);
    let (leaf_der, _) = leaf_cert("mx.foobar.org", &intermediate);
    let unrelated = root_ca("Unrelated CA");
    let chain = vec![leaf_der, intermediate.der.clone(), unrelated.der.clone()];

    let record = tlsa(vec![ta_full_sha256(&unrelated.der)]);
    assert!(
        record
            .verify(0, "mx.foobar.org", &["mx.foobar.org"], Some(&chain))
            .is_err()
    );
}

#[test]
fn dane_ta_rejects_expired_intermediate() {
    let root = root_ca("Validity Root");
    let int_key = KeyPair::generate().unwrap();
    let mut int_params = ca_params("Expired Intermediate");
    int_params.not_before = date_time_ymd(2018, 1, 1);
    int_params.not_after = date_time_ymd(2021, 1, 1);
    let int_cert = int_params.signed_by(&int_key, &root.issuer).unwrap();
    let intermediate = TestCa {
        der: int_cert.der().clone(),
        spki: int_key.subject_public_key_info(),
        issuer: Issuer::new(int_params, int_key),
    };
    let (leaf_der, _) = leaf_cert("mx.foobar.org", &intermediate);
    let chain = vec![leaf_der, intermediate.der.clone(), root.der.clone()];

    let record = tlsa(vec![ta_full_sha256(&root.der)]);
    assert!(
        record
            .verify(0, "mx.foobar.org", &["mx.foobar.org"], Some(&chain))
            .is_err()
    );
}

#[test]
fn dane_ta_bare_key_anchors_chain() {
    let root = root_ca("Bare Key Root");
    let intermediate = sub_ca("Bare Key Intermediate", &root);
    let (leaf_der, _) = leaf_cert("mx.foobar.org", &intermediate);
    let chain = vec![leaf_der, intermediate.der.clone()];

    let record = tlsa(vec![ta_spki_full(&root.spki)]);
    assert!(
        record
            .verify(0, "mx.foobar.org", &["mx.foobar.org"], Some(&chain))
            .is_ok()
    );

    let unrelated = root_ca("Bare Key Unrelated");
    let wrong = tlsa(vec![ta_spki_full(&unrelated.spki)]);
    assert!(
        wrong
            .verify(0, "mx.foobar.org", &["mx.foobar.org"], Some(&chain))
            .is_err()
    );
}

fn ca_params(common_name: &str) -> CertificateParams {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
}

fn root_ca(common_name: &str) -> TestCa {
    let key = KeyPair::generate().unwrap();
    let params = ca_params(common_name);
    let cert = params.self_signed(&key).unwrap();
    let der = cert.der().clone();
    let spki = key.subject_public_key_info();
    TestCa {
        issuer: Issuer::new(params, key),
        der,
        spki,
    }
}

fn sub_ca(common_name: &str, parent: &TestCa) -> TestCa {
    let key = KeyPair::generate().unwrap();
    let params = ca_params(common_name);
    let cert = params.signed_by(&key, &parent.issuer).unwrap();
    let der = cert.der().clone();
    let spki = key.subject_public_key_info();
    TestCa {
        issuer: Issuer::new(params, key),
        der,
        spki,
    }
}

fn sub_ca_path_len(common_name: &str, parent: &TestCa, path_len: u8) -> TestCa {
    let key = KeyPair::generate().unwrap();
    let mut params = ca_params(common_name);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(path_len));
    let cert = params.signed_by(&key, &parent.issuer).unwrap();
    let der = cert.der().clone();
    let spki = key.subject_public_key_info();
    TestCa {
        issuer: Issuer::new(params, key),
        der,
        spki,
    }
}

fn leaf_cert(san: &str, parent: &TestCa) -> (CertificateDer<'static>, Vec<u8>) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![san.to_string()]).unwrap();
    params.distinguished_name.push(DnType::CommonName, san);
    let cert = params.signed_by(&key, &parent.issuer).unwrap();
    (cert.der().clone(), key.subject_public_key_info())
}

fn ee_spki_sha256(spki: &[u8]) -> TlsaEntry {
    TlsaEntry {
        is_end_entity: true,
        is_spki: true,
        matching: TlsaMatching::Sha256,
        data: Sha256::digest(spki).to_vec(),
    }
}

fn ta_full_sha256(der: &CertificateDer<'_>) -> TlsaEntry {
    TlsaEntry {
        is_end_entity: false,
        is_spki: false,
        matching: TlsaMatching::Sha256,
        data: Sha256::digest(der.as_ref()).to_vec(),
    }
}

fn ta_spki_full(spki: &[u8]) -> TlsaEntry {
    TlsaEntry {
        is_end_entity: false,
        is_spki: true,
        matching: TlsaMatching::Full,
        data: spki.to_vec(),
    }
}

fn tlsa(entries: Vec<TlsaEntry>) -> Tlsa {
    Tlsa {
        has_end_entities: entries.iter().any(|entry| entry.is_end_entity),
        has_intermediates: entries.iter().any(|entry| !entry.is_end_entity),
        entries,
    }
}

#[test]
fn dane_ta_does_not_match_leaf() {
    let root = root_ca("Depth Root");
    let intermediate = sub_ca("Depth Intermediate", &root);
    let (leaf_der, _) = leaf_cert("mx.foobar.org", &intermediate);
    let chain = vec![leaf_der.clone(), intermediate.der.clone(), root.der.clone()];

    let record = tlsa(vec![ta_full_sha256(&leaf_der)]);
    assert!(
        record
            .verify(0, "mx.foobar.org", &["mx.foobar.org"], Some(&chain))
            .is_err()
    );

    let ee = tlsa(vec![ee_full_sha256(&leaf_der)]);
    assert!(
        ee.verify(0, "mx.foobar.org", &["mx.foobar.org"], Some(&chain))
            .is_ok()
    );
}

#[test]
fn dane_ta_bare_key_in_chain() {
    let root = root_ca("In Chain Root");
    let intermediate = sub_ca("In Chain Intermediate", &root);
    let (leaf_der, _) = leaf_cert("mx.foobar.org", &intermediate);
    let chain = vec![leaf_der, intermediate.der.clone(), root.der.clone()];

    let record = tlsa(vec![ta_spki_full(&intermediate.spki)]);
    assert!(
        record
            .verify(0, "mx.foobar.org", &["mx.foobar.org"], Some(&chain))
            .is_ok()
    );
}

#[test]
fn dane_ta_bare_key_anchors_deep_chain() {
    let root = root_ca("Deep Bare Key Root");
    let intermediate1 = sub_ca("Deep Bare Key Intermediate 1", &root);
    let intermediate2 = sub_ca("Deep Bare Key Intermediate 2", &intermediate1);
    let (leaf_der, _) = leaf_cert("mx.foobar.org", &intermediate2);
    let chain = vec![
        leaf_der,
        intermediate2.der.clone(),
        intermediate1.der.clone(),
    ];

    let record = tlsa(vec![ta_spki_full(&root.spki)]);
    assert!(
        record
            .verify(0, "mx.foobar.org", &["mx.foobar.org"], Some(&chain))
            .is_ok()
    );

    let unrelated = root_ca("Deep Bare Key Unrelated");
    let wrong = tlsa(vec![ta_spki_full(&unrelated.spki)]);
    assert!(
        wrong
            .verify(0, "mx.foobar.org", &["mx.foobar.org"], Some(&chain))
            .is_err()
    );
}

#[test]
fn dane_ta_rejects_path_len_violation() {
    let root = root_ca("Path Len Root");
    let constrained = sub_ca_path_len("Path Len Constrained", &root, 0);
    let extra = sub_ca("Path Len Extra", &constrained);
    let (leaf_der, _) = leaf_cert("mx.foobar.org", &extra);
    let chain = vec![
        leaf_der,
        extra.der.clone(),
        constrained.der.clone(),
        root.der.clone(),
    ];

    let record = tlsa(vec![ta_full_sha256(&root.der)]);
    assert!(
        record
            .verify(0, "mx.foobar.org", &["mx.foobar.org"], Some(&chain))
            .is_err()
    );

    let allowed = root_ca("Path Len Allowed Root");
    let constrained = sub_ca_path_len("Path Len Allowed Constrained", &allowed, 0);
    let (leaf_der, _) = leaf_cert("mx.foobar.org", &constrained);
    let chain = vec![leaf_der, constrained.der.clone(), allowed.der.clone()];

    let record = tlsa(vec![ta_full_sha256(&allowed.der)]);
    assert!(
        record
            .verify(0, "mx.foobar.org", &["mx.foobar.org"], Some(&chain))
            .is_ok()
    );
}

#[test]
fn dane_ta_validates_unordered_padded_chain() {
    let root = root_ca("Unordered Root");
    let intermediate = sub_ca("Unordered Intermediate", &root);
    let (leaf_der, _) = leaf_cert("mx.foobar.org", &intermediate);
    let noise = root_ca("Unordered Noise");
    let chain = vec![
        leaf_der,
        root.der.clone(),
        noise.der.clone(),
        intermediate.der.clone(),
    ];

    let record = tlsa(vec![ta_full_sha256(&intermediate.der)]);
    assert!(
        record
            .verify(0, "mx.foobar.org", &["mx.foobar.org"], Some(&chain))
            .is_ok()
    );
}

#[test]
fn dane_ta_rejects_non_ca_issuer() {
    let root = root_ca("Non CA Root");
    let forged = sub_ca_non_ca("Non CA Intermediate", &root);
    let (leaf_der, _) = leaf_cert("mx.foobar.org", &forged);
    let chain = vec![leaf_der, forged.der.clone(), root.der.clone()];

    let record = tlsa(vec![ta_full_sha256(&root.der)]);
    assert!(
        record
            .verify(0, "mx.foobar.org", &["mx.foobar.org"], Some(&chain))
            .is_err()
    );
}

#[test]
fn dane_ta_rejects_ee_without_server_auth_eku() {
    let root = root_ca("EKU Root");
    let intermediate = sub_ca("EKU Intermediate", &root);
    let (leaf_der, _) = leaf_cert_eku(
        "mx.foobar.org",
        &intermediate,
        vec![ExtendedKeyUsagePurpose::ClientAuth],
    );
    let chain = vec![leaf_der, intermediate.der.clone(), root.der.clone()];

    let record = tlsa(vec![ta_full_sha256(&intermediate.der)]);
    assert!(
        record
            .verify(0, "mx.foobar.org", &["mx.foobar.org"], Some(&chain))
            .is_err()
    );
}

#[test]
fn dane_ta_accepts_ee_with_server_auth_eku() {
    let root = root_ca("EKU OK Root");
    let intermediate = sub_ca("EKU OK Intermediate", &root);
    let (leaf_der, _) = leaf_cert_eku(
        "mx.foobar.org",
        &intermediate,
        vec![ExtendedKeyUsagePurpose::ServerAuth],
    );
    let chain = vec![leaf_der, intermediate.der.clone(), root.der.clone()];

    let record = tlsa(vec![ta_full_sha256(&intermediate.der)]);
    assert!(
        record
            .verify(0, "mx.foobar.org", &["mx.foobar.org"], Some(&chain))
            .is_ok()
    );
}

#[test]
fn dane_ta_ignores_common_name() {
    let root = root_ca("CN Root");
    let intermediate = sub_ca("CN Intermediate", &root);
    let leaf_der = leaf_cert_cn_only("mx.foobar.org", &intermediate);
    let chain = vec![leaf_der, intermediate.der.clone(), root.der.clone()];

    let record = tlsa(vec![ta_full_sha256(&intermediate.der)]);
    assert!(
        record
            .verify(0, "mx.foobar.org", &["mx.foobar.org"], Some(&chain))
            .is_err()
    );
}

fn sub_ca_non_ca(common_name: &str, parent: &TestCa) -> TestCa {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::ExplicitNoCa;
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    let cert = params.signed_by(&key, &parent.issuer).unwrap();
    let der = cert.der().clone();
    let spki = key.subject_public_key_info();
    TestCa {
        issuer: Issuer::new(params, key),
        der,
        spki,
    }
}

fn leaf_cert_eku(
    san: &str,
    parent: &TestCa,
    ekus: Vec<ExtendedKeyUsagePurpose>,
) -> (CertificateDer<'static>, Vec<u8>) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![san.to_string()]).unwrap();
    params.distinguished_name.push(DnType::CommonName, san);
    params.extended_key_usages = ekus;
    let cert = params.signed_by(&key, &parent.issuer).unwrap();
    (cert.der().clone(), key.subject_public_key_info())
}

fn leaf_cert_cn_only(common_name: &str, parent: &TestCa) -> CertificateDer<'static> {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    let cert = params.signed_by(&key, &parent.issuer).unwrap();
    cert.der().clone()
}

fn ee_full_sha256(der: &CertificateDer<'_>) -> TlsaEntry {
    TlsaEntry {
        is_end_entity: true,
        is_spki: false,
        matching: TlsaMatching::Sha256,
        data: Sha256::digest(der.as_ref()).to_vec(),
    }
}

#[tokio::test]
#[ignore = "live network test: requires outbound TCP port 25 and a DNSSEC-validating resolver path"]
async fn dane_live_smtp_hosts() {
    use mail_auth::hickory_resolver::{
        TokioResolver,
        config::{CLOUDFLARE, ResolverConfig, ResolverOpts},
        net::runtime::TokioRuntimeProvider,
        proto::rr::{
            Name, RData,
            rdata::tlsa::{CertUsage, Matching, Selector},
        },
    };
    use smtp::outbound::client::{SmtpClient, StartTlsResult};
    use std::net::{IpAddr, SocketAddr};
    use tokio::io::AsyncWriteExt;
    use tokio_rustls::TlsConnector;
    use utils::tls::build_tls_connector;

    enum DaneProbe {
        Verified {
            mx: String,
            usages: Vec<String>,
            chain_len: usize,
            native_ee: bool,
            native_ta: bool,
            webpki_forced: Option<bool>,
        },
        Skipped(String),
        Failed {
            mx: String,
            reason: String,
        },
    }

    async fn probe(resolver: &TokioResolver, connector: &TlsConnector, domain: &str) -> DaneProbe {
        let mx_lookup = match resolver.mx_lookup(format!("{domain}.")).await {
            Ok(lookup) => lookup,
            Err(err) => return DaneProbe::Skipped(format!("MX lookup failed: {err}")),
        };
        let mut mx_hosts: Vec<(u16, String)> = mx_lookup
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                RData::MX(mx) => Some((
                    mx.preference,
                    mx.exchange.to_string().trim_end_matches('.').to_string(),
                )),
                _ => None,
            })
            .collect();
        mx_hosts.sort_by_key(|(preference, _)| *preference);
        if mx_hosts.is_empty() {
            mx_hosts.push((0, domain.to_string()));
        }

        for (_, mx) in &mx_hosts {
            let tlsa_name = match Name::from_str_relaxed(format!("_25._tcp.{mx}.")) {
                Ok(name) => name,
                Err(err) => {
                    return DaneProbe::Skipped(format!("invalid TLSA name for {mx}: {err}"));
                }
            };
            let tlsa_lookup = match resolver.tlsa_lookup(tlsa_name).await {
                Ok(lookup) => lookup,
                Err(_) => continue,
            };

            let mut entries = Vec::new();
            let mut usages = Vec::new();
            let mut has_end_entities = false;
            let mut has_intermediates = false;
            for record in tlsa_lookup.answers() {
                if let RData::TLSA(tlsa) = &record.data {
                    if !record.proof.is_secure() {
                        continue;
                    }
                    let is_end_entity = match tlsa.cert_usage {
                        CertUsage::DaneEe => true,
                        CertUsage::DaneTa => false,
                        _ => continue,
                    };
                    let matching = match tlsa.matching {
                        Matching::Raw => TlsaMatching::Full,
                        Matching::Sha256 => TlsaMatching::Sha256,
                        Matching::Sha512 => TlsaMatching::Sha512,
                        _ => continue,
                    };
                    let is_spki = match tlsa.selector {
                        Selector::Spki => true,
                        Selector::Full => false,
                        _ => continue,
                    };
                    if is_end_entity {
                        has_end_entities = true;
                    } else {
                        has_intermediates = true;
                    }
                    let usage = format!(
                        "{} {} {}",
                        if is_end_entity { 3 } else { 2 },
                        if is_spki { 1 } else { 0 },
                        match matching {
                            TlsaMatching::Full => 0,
                            TlsaMatching::Sha256 => 1,
                            TlsaMatching::Sha512 => 2,
                        }
                    );
                    if !usages.contains(&usage) {
                        usages.push(usage);
                    }
                    entries.push(TlsaEntry {
                        is_end_entity,
                        is_spki,
                        matching,
                        data: tlsa.cert_data.clone(),
                    });
                }
            }
            if entries.is_empty() {
                continue;
            }
            let tlsa = Tlsa {
                entries,
                has_end_entities,
                has_intermediates,
            };

            let mut ips: Vec<IpAddr> = match resolver.lookup_ip(format!("{mx}.")).await {
                Ok(ips) => ips.iter().collect(),
                Err(err) => {
                    return DaneProbe::Skipped(format!("address lookup failed for {mx}: {err}"));
                }
            };
            if ips.is_empty() {
                return DaneProbe::Skipped(format!("no A/AAAA records for {mx}"));
            }
            ips.sort_by_key(|ip| ip.is_ipv6());

            let mut connected = None;
            let mut last_error = String::new();
            for ip in ips {
                match SmtpClient::connect(SocketAddr::new(ip, 25), Duration::from_secs(20), 0).await
                {
                    Ok(client) => {
                        connected = Some(client);
                        break;
                    }
                    Err(err) => {
                        last_error = format!("connect to [{ip}]:25 ({mx}) failed: {err:?}");
                    }
                }
            }
            let mut client = match connected {
                Some(client) => client,
                None => return DaneProbe::Skipped(last_error),
            };
            if let Err(err) = client.read_greeting(mx).await {
                return DaneProbe::Skipped(format!("greeting from {mx} failed: {err:?}"));
            }
            if client
                .stream
                .write_all(b"EHLO dane-live-test.invalid\r\n")
                .await
                .is_err()
            {
                return DaneProbe::Skipped(format!("EHLO write to {mx} failed"));
            }
            let _ = client.stream.flush().await;
            let capabilities = match client.read_ehlo().await {
                Ok(capabilities) => capabilities,
                Err(err) => return DaneProbe::Skipped(format!("EHLO to {mx} failed: {err:?}")),
            };

            let tls_client = match client.try_start_tls(connector, mx, &capabilities).await {
                StartTlsResult::Success { smtp_client } => smtp_client,
                StartTlsResult::Unavailable { .. } => {
                    return DaneProbe::Skipped(format!("{mx} does not offer STARTTLS"));
                }
                StartTlsResult::Error { error } => {
                    return DaneProbe::Skipped(format!("STARTTLS with {mx} failed: {error:?}"));
                }
            };

            let certificates = match tls_client.tls_connection().peer_certificates() {
                Some(certificates) => certificates.to_vec(),
                None => {
                    return DaneProbe::Failed {
                        mx: mx.clone(),
                        reason: "server presented no certificates after TLS handshake".into(),
                    };
                }
            };

            let reference_ids = [mx.as_str(), domain];

            if let Err(status) = tlsa.verify(0, mx, &reference_ids, Some(&certificates)) {
                return DaneProbe::Failed {
                    mx: mx.clone(),
                    reason: format!("TLSA verification rejected a live DANE host: {status:?}"),
                };
            }

            let verify_subset = |keep_end_entity: bool| {
                let entries: Vec<TlsaEntry> = tlsa
                    .entries
                    .iter()
                    .filter(|entry| entry.is_end_entity == keep_end_entity)
                    .cloned()
                    .collect();
                if entries.is_empty() {
                    return false;
                }
                Tlsa {
                    has_end_entities: keep_end_entity,
                    has_intermediates: !keep_end_entity,
                    entries,
                }
                .verify(0, mx, &reference_ids, Some(&certificates))
                .is_ok()
            };
            let native_ee = verify_subset(true);
            let native_ta = verify_subset(false);

            // Force the rustls-webpki trust-chain path
            let webpki_forced = (certificates.len() >= 2).then(|| {
                let anchor = certificates.last().unwrap();
                Tlsa {
                    entries: vec![TlsaEntry {
                        is_end_entity: false,
                        is_spki: false,
                        matching: TlsaMatching::Sha256,
                        data: Sha256::digest(anchor.as_ref()).to_vec(),
                    }],
                    has_end_entities: false,
                    has_intermediates: true,
                }
                .verify(0, mx, &reference_ids, Some(&certificates))
                .is_ok()
            });

            return DaneProbe::Verified {
                mx: mx.clone(),
                usages,
                chain_len: certificates.len(),
                native_ee,
                native_ta,
                webpki_forced,
            };
        }

        DaneProbe::Skipped("no MX host published usable secure TLSA records".into())
    }

    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();

    let mut opts = ResolverOpts::default();
    opts.validate = true;
    opts.cache_size = 0;
    let resolver = TokioResolver::builder_with_config(
        ResolverConfig::udp_and_tcp(&CLOUDFLARE),
        TokioRuntimeProvider::default(),
    )
    .with_options(opts)
    .build()
    .expect("failed to build DNSSEC-validating resolver");
    let connector = build_tls_connector(true).expect("failed to build TLS connector");

    let domains = [
        "dukhovni.org",
        "nlnetlabs.nl",
        "debian.org",
        "freebsd.org",
        "posteo.de",
        "mailbox.org",
    ];

    let mut verified = 0usize;
    let mut webpki_chain_validated = 0usize;
    let mut hard_failures = Vec::new();
    for domain in domains {
        match probe(&resolver, &connector, domain).await {
            DaneProbe::Verified {
                mx,
                usages,
                chain_len,
                native_ee,
                native_ta,
                webpki_forced,
            } => {
                verified += 1;
                let native_path = match (native_ee, native_ta) {
                    (true, true) => "EE+TA",
                    (true, false) => "EE (no webpki)",
                    (false, true) => "TA (webpki)",
                    (false, false) => "?",
                };
                let forced = match webpki_forced {
                    Some(true) => {
                        webpki_chain_validated += 1;
                        "PASS"
                    }
                    Some(false) => "FAIL",
                    None => "n/a (single-cert chain)",
                };
                if native_ta {
                    webpki_chain_validated += 1;
                }
                println!(
                    "[ OK ] {domain}: MX {mx} | TLSA [{}] | chain {chain_len} certs | native path: {native_path} | forced webpki-TA vs real chain: {forced}",
                    usages.join(", ")
                );
                if webpki_forced == Some(false) {
                    hard_failures.push(format!(
                        "{domain} (MX {mx}): rustls-webpki rejected the server's own presented chain"
                    ));
                }
            }
            DaneProbe::Skipped(reason) => {
                println!("[SKIP] {domain}: {reason}");
            }
            DaneProbe::Failed { mx, reason } => {
                println!("[FAIL] {domain} (MX {mx}): {reason}");
                hard_failures.push(format!("{domain} (MX {mx}): {reason}"));
            }
        }
    }

    assert!(
        hard_failures.is_empty(),
        "DANE verification rejected hosts that published valid secure TLSA records: {hard_failures:#?}"
    );
    assert!(
        verified > 0,
        "no DANE-enabled host could be reached and verified; check outbound port 25 and DNSSEC connectivity"
    );
    assert!(
        webpki_chain_validated > 0,
        "no host exercised the rustls-webpki trust-chain path; the live test only covered DANE-EE direct matches"
    );
}
