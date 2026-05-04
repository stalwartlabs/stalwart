/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    Server,
    config::smtp::queue::{QueueExpiry, QueueName},
};
use registry::{
    schema::{
        enums::{
            ArfAuthFailureType, ArfDeliveryResult, ArfFeedbackType, ArfIdentityAlignment,
            DkimAuthResult, DmarcAlignment, DmarcDisposition, DmarcResult, SpfAuthResult,
            SpfDomainScope, TlsPolicyType, TlsResultType,
        },
        prelude::ObjectType,
        structs::{
            ArfExternalReport, ArfFeedbackReport, DmarcDkimResult, DmarcExternalReport,
            DmarcInternalReport, DmarcReport, DmarcReportRecord, DmarcSpfResult, TlsExternalReport,
            TlsFailureDetails, TlsInternalReport, TlsReport, TlsReportPolicy,
        },
    },
    types::{
        EnumImpl, ObjectImpl, datetime::UTCDateTime, float::Float, ipaddr::IpAddr, list::List,
        map::Map,
    },
};
use smtp::{
    queue::{
        Error, ErrorDetails, FROM_AUTHENTICATED, FROM_DSN, FROM_REPORT, HostResponse, Message,
        MessageWrapper, RCPT_DSN_SENT, RCPT_SPAM_PAYLOAD, Recipient, Schedule, Status,
        UnexpectedResponse,
    },
    reporting::index::{ExternalReportIndex, InternalReportIndex},
};
use smtp_proto::Response;
use std::net::Ipv4Addr;
use store::write::{BatchBuilder, RegistryClass, ValueClass};
use types::blob_hash::BlobHash;

pub async fn insert_test_data(server: &Server) {
    let mut hashes = Vec::new();
    let future = one_year_from_now_u64();
    for message in sample_raw_messages() {
        let (hash, _) = server
            .put_temporary_blob(u32::MAX, message.as_bytes(), future)
            .await
            .unwrap();
        hashes.push(hash);
    }

    for message in sample_queued_messages(hashes) {
        let qm = MessageWrapper::new(
            message,
            server.inner.data.queue_id_gen.generate(),
            QueueName::default(),
        );
        assert!(qm.save_changes(server, None).await);
    }

    for report in sample_tls_internal_reports() {
        let object_id = ObjectType::TlsInternalReport.to_id();
        let item_id = server.inner.data.queue_id_gen.generate();
        let mut batch = BatchBuilder::new();
        batch.clear(report.primary_key());
        report.write_ops(&mut batch, item_id, true);
        let report_bytes = report.to_pickled_vec();
        batch.set(
            ValueClass::Registry(RegistryClass::Item { object_id, item_id }),
            report_bytes,
        );
        server.store().write(batch.build_all()).await.unwrap();
    }

    for report in sample_dmarc_internal_reports() {
        let object_id = ObjectType::DmarcInternalReport.to_id();
        let item_id = server.inner.data.queue_id_gen.generate();
        let mut batch = BatchBuilder::new();
        batch.clear(report.primary_key());
        report.write_ops(&mut batch, item_id, true);
        let report_bytes = report.to_pickled_vec();
        batch.set(
            ValueClass::Registry(RegistryClass::Item { object_id, item_id }),
            report_bytes,
        );
        server.store().write(batch.build_all()).await.unwrap();
    }

    for report in sample_tls_external_reports() {
        let mut batch = BatchBuilder::new();
        let item_id = server.inner.data.queue_id_gen.generate();
        report.write_ops(&mut batch, item_id, true);
        server.store().write(batch.build_all()).await.unwrap();
    }

    for report in sample_dmarc_external_reports() {
        let mut batch = BatchBuilder::new();
        let item_id = server.inner.data.queue_id_gen.generate();
        report.write_ops(&mut batch, item_id, true);
        server.store().write(batch.build_all()).await.unwrap();
    }

    for report in sample_arf_external_reports() {
        let mut batch = BatchBuilder::new();
        let item_id = server.inner.data.queue_id_gen.generate();
        report.write_ops(&mut batch, item_id, true);
        server.store().write(batch.build_all()).await.unwrap();
    }
}

fn sample_queued_messages(blob_hashes: Vec<BlobHash>) -> Vec<Message> {
    assert!(
        blob_hashes.len() >= 3,
        "Need at least 3 blob hashes for sample queued messages"
    );
    let future = one_year_from_now_u64();
    let now = store::write::now();
    let raw_messages = sample_raw_messages();

    vec![
        // Message 1: Normal outbound message with two recipients, one scheduled and one completed
        Message {
            created: now,
            blob_hash: blob_hashes[0].clone(),
            return_path: "sender@myserver.com".into(),
            recipients: vec![
                Recipient {
                    address: "alice@example.com".into(),
                    retry: Schedule {
                        due: future,
                        inner: 0,
                    },
                    notify: Schedule {
                        due: future,
                        inner: 0,
                    },
                    expires: QueueExpiry::Ttl(365 * 24 * 3600),
                    queue: Default::default(),
                    status: Status::Scheduled,
                    flags: 0,
                    orcpt: None,
                },
                Recipient {
                    address: "bob@example.org".into(),
                    retry: Schedule {
                        due: future,
                        inner: 2,
                    },
                    notify: Schedule {
                        due: future,
                        inner: 1,
                    },
                    expires: QueueExpiry::Ttl(365 * 24 * 3600),
                    queue: Default::default(),
                    status: Status::Completed(HostResponse {
                        hostname: "mx.example.org".into(),
                        response: Response {
                            code: 250,
                            esc: [2, 1, 5],
                            message: "OK".into(),
                        },
                    }),
                    flags: RCPT_DSN_SENT,
                    orcpt: Some("rfc822;bob@example.org".into()),
                },
            ],
            received_from_ip: std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            received_via_port: 25,
            flags: FROM_AUTHENTICATED,
            env_id: Some("env-001".into()),
            priority: 0,
            size: raw_messages[0].len() as u64,
            quota_keys: Box::new([]),
        },
        // Message 2: DSN bounce message with a temporary failure recipient
        Message {
            created: now,
            blob_hash: blob_hashes[1].clone(),
            return_path: "".into(),
            recipients: vec![Recipient {
                address: "postmaster@remote.net".into(),
                retry: Schedule {
                    due: future,
                    inner: 3,
                },
                notify: Schedule {
                    due: future,
                    inner: 0,
                },
                expires: QueueExpiry::Ttl(365 * 24 * 3600),
                queue: Default::default(),
                status: Status::TemporaryFailure(ErrorDetails {
                    entity: "mx.remote.net".into(),
                    details: Error::UnexpectedResponse(UnexpectedResponse {
                        command: "RCPT TO".into(),
                        response: Response {
                            code: 450,
                            esc: [4, 2, 1],
                            message: "Mailbox temporarily unavailable".into(),
                        },
                    }),
                }),
                flags: 0,
                orcpt: None,
            }],
            received_from_ip: std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            received_via_port: 587,
            flags: FROM_DSN,
            env_id: None,
            priority: -5,
            size: raw_messages[1].len() as u64,
            quota_keys: Box::new([]),
        },
        // Message 3: Report message with a temporary failure recipient
        Message {
            created: now,
            blob_hash: blob_hashes[2].clone(),
            return_path: "reports@myserver.com".into(),
            recipients: vec![Recipient {
                address: "abuse@bigcorp.com".into(),
                retry: Schedule {
                    due: future,
                    inner: 0,
                },
                notify: Schedule {
                    due: future,
                    inner: 2,
                },
                expires: QueueExpiry::Ttl(365 * 24 * 3600),
                queue: Default::default(),
                status: Status::TemporaryFailure(ErrorDetails {
                    entity: "mx.bigcorp.com".into(),
                    details: Error::ConnectionError("Rejected by policy".into()),
                }),
                flags: RCPT_SPAM_PAYLOAD,
                orcpt: None,
            }],
            received_from_ip: std::net::IpAddr::V4(Ipv4Addr::new(172, 16, 0, 5)),
            received_via_port: 465,
            flags: FROM_REPORT | FROM_AUTHENTICATED,
            env_id: Some("env-report-99".into()),
            priority: 10,
            size: raw_messages[2].len() as u64,
            quota_keys: Box::new([]),
        },
    ]
}

fn sample_raw_messages() -> Vec<String> {
    vec![
        // Raw message 1: Normal outbound email (matches Message 1)
        concat!(
            "From: sender@myserver.com\r\n",
            "To: alice@example.com, bob@example.org\r\n",
            "Subject: Quarterly Report Q1 2027\r\n",
            "Date: Sat, 12 Apr 2027 09:00:00 +0000\r\n",
            "Message-ID: <msg-001@myserver.com>\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "Hi team,\r\n",
            "\r\n",
            "Please find attached the quarterly report for Q1 2027.\r\n",
            "Let me know if you have any questions.\r\n",
            "\r\n",
            "Best regards,\r\n",
            "The Sender\r\n",
        )
        .to_string(),
        // Raw message 2: DSN bounce (matches Message 2)
        concat!(
            "From: <>\r\n",
            "To: postmaster@remote.net\r\n",
            "Subject: Delivery Status Notification (Failure)\r\n",
            "Date: Sat, 12 Apr 2027 09:05:00 +0000\r\n",
            "Message-ID: <dsn-002@myserver.com>\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/report; report-type=delivery-status;\r\n",
            "    boundary=\"boundary-dsn-002\"\r\n",
            "\r\n",
            "--boundary-dsn-002\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "This is an automatically generated Delivery Status Notification.\r\n",
            "Delivery to the following recipient failed temporarily:\r\n",
            "\r\n",
            "    postmaster@remote.net\r\n",
            "\r\n",
            "The server will retry delivery.\r\n",
            "\r\n",
            "--boundary-dsn-002\r\n",
            "Content-Type: message/delivery-status\r\n",
            "\r\n",
            "Reporting-MTA: dns; myserver.com\r\n",
            "Arrival-Date: Sat, 12 Apr 2027 09:00:00 +0000\r\n",
            "\r\n",
            "Final-Recipient: rfc822; postmaster@remote.net\r\n",
            "Action: delayed\r\n",
            "Status: 4.2.1\r\n",
            "Remote-MTA: dns; mx.remote.net\r\n",
            "Diagnostic-Code: smtp; 450 Mailbox temporarily unavailable\r\n",
            "\r\n",
            "--boundary-dsn-002--\r\n",
        )
        .to_string(),
        // Raw message 3: Report message (matches Message 3)
        concat!(
            "From: reports@myserver.com\r\n",
            "To: abuse@bigcorp.com\r\n",
            "Subject: DMARC Aggregate Report for bigcorp.com\r\n",
            "Date: Sat, 12 Apr 2027 09:10:00 +0000\r\n",
            "Message-ID: <report-003@myserver.com>\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/mixed;\r\n",
            "    boundary=\"boundary-report-003\"\r\n",
            "\r\n",
            "--boundary-report-003\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "This is a DMARC aggregate report for the domain bigcorp.com\r\n",
            "generated by myserver.com.\r\n",
            "\r\n",
            "Report period: 2027-04-11T00:00:00Z to 2027-04-12T00:00:00Z\r\n",
            "\r\n",
            "--boundary-report-003\r\n",
            "Content-Type: application/gzip\r\n",
            "Content-Disposition: attachment;\r\n",
            "    filename=\"myserver.com!bigcorp.com!1744329600!1744416000.xml.gz\"\r\n",
            "Content-Transfer-Encoding: base64\r\n",
            "\r\n",
            "H4sIAAAAAAAAA2NgGAWjYBSMglEwCkbBKBgFo2AUDAIAAP//\r\n",
            "\r\n",
            "--boundary-report-003--\r\n",
        )
        .to_string(),
    ]
}

fn sample_tls_internal_reports() -> Vec<TlsInternalReport> {
    let future = one_year_from_now();

    vec![
        // Report 1: Successful TLS sessions, STS policy
        TlsInternalReport {
            created_at: now(),
            deliver_at: future,
            domain: "example.com".to_string(),
            http_rua: Map::new(vec!["https://example.com/tlsrpt".to_string()]),
            mail_rua: Map::new(vec!["mailto:tls-reports@example.com".to_string()]),
            policy_identifiers: Map::new(vec![1]),
            report: TlsReport {
                contact_info: Some("admin@myserver.com".to_string()),
                date_range_end: now(),
                date_range_start: days_ago(1),
                organization_name: Some("My Mail Server".to_string()),
                policies: List::from(vec![TlsReportPolicy {
                    failure_details: List::from(vec![]),
                    mx_hosts: Map::new(vec!["mx1.example.com".to_string()]),
                    policy_domain: "example.com".to_string(),
                    policy_strings: Map::new(vec![
                        "mode: enforce".to_string(),
                        "max_age: 86400".to_string(),
                    ]),
                    policy_type: TlsPolicyType::Sts,
                    total_failed_sessions: 0,
                    total_successful_sessions: 150,
                }]),
                report_id: "tls-int-report-001".to_string(),
            },
        },
        // Report 2: Mixed results with certificate mismatch failures
        TlsInternalReport {
            created_at: now(),
            deliver_at: future,
            domain: "secure-mail.org".to_string(),
            http_rua: Map::new(vec![]),
            mail_rua: Map::new(vec![
                "mailto:tlsrpt@secure-mail.org".to_string(),
                "mailto:security@secure-mail.org".to_string(),
            ]),
            policy_identifiers: Map::new(vec![2, 3]),
            report: TlsReport {
                contact_info: Some("postmaster@myserver.com".to_string()),
                date_range_end: now(),
                date_range_start: days_ago(1),
                organization_name: Some("My Mail Server".to_string()),
                policies: List::from(vec![TlsReportPolicy {
                    failure_details: List::from(vec![TlsFailureDetails {
                        additional_information: Some(
                            "Certificate CN does not match hostname".to_string(),
                        ),
                        failed_session_count: 5,
                        failure_reason_code: Some("certificate-host-mismatch".to_string()),
                        receiving_ip: Some(IpAddr(std::net::IpAddr::V4(Ipv4Addr::new(
                            203, 0, 113, 10,
                        )))),
                        receiving_mx_helo: Some("mx.secure-mail.org".to_string()),
                        receiving_mx_hostname: Some("mx.secure-mail.org".to_string()),
                        result_type: TlsResultType::CertificateHostMismatch,
                        sending_mta_ip: Some(IpAddr(std::net::IpAddr::V4(Ipv4Addr::new(
                            192, 0, 2, 1,
                        )))),
                    }]),
                    mx_hosts: Map::new(vec!["mx.secure-mail.org".to_string()]),
                    policy_domain: "secure-mail.org".to_string(),
                    policy_strings: Map::new(vec!["mode: testing".to_string()]),
                    policy_type: TlsPolicyType::Sts,
                    total_failed_sessions: 5,
                    total_successful_sessions: 95,
                }]),
                report_id: "tls-int-report-002".to_string(),
            },
        },
        // Report 3: DANE/TLSA policy with validation failure
        TlsInternalReport {
            created_at: now(),
            deliver_at: future,
            domain: "dane-enabled.net".to_string(),
            http_rua: Map::new(vec!["https://dane-enabled.net/tlsrpt".to_string()]),
            mail_rua: Map::new(vec![]),
            policy_identifiers: Map::new(vec![4]),
            report: TlsReport {
                contact_info: None,
                date_range_end: now(),
                date_range_start: days_ago(1),
                organization_name: Some("My Mail Server".to_string()),
                policies: List::from(vec![TlsReportPolicy {
                    failure_details: List::from(vec![TlsFailureDetails {
                        additional_information: None,
                        failed_session_count: 2,
                        failure_reason_code: Some("tlsa-invalid".to_string()),
                        receiving_ip: Some(IpAddr(std::net::IpAddr::V4(Ipv4Addr::new(
                            198, 51, 100, 25,
                        )))),
                        receiving_mx_helo: Some("mail.dane-enabled.net".to_string()),
                        receiving_mx_hostname: Some("mail.dane-enabled.net".to_string()),
                        result_type: TlsResultType::TlsaInvalid,
                        sending_mta_ip: Some(IpAddr(std::net::IpAddr::V4(Ipv4Addr::new(
                            192, 0, 2, 1,
                        )))),
                    }]),
                    mx_hosts: Map::new(vec!["mail.dane-enabled.net".to_string()]),
                    policy_domain: "dane-enabled.net".to_string(),
                    policy_strings: Map::new(vec![]),
                    policy_type: TlsPolicyType::Tlsa,
                    total_failed_sessions: 2,
                    total_successful_sessions: 48,
                }]),
                report_id: "tls-int-report-003".to_string(),
            },
        },
    ]
}

fn sample_dmarc_internal_reports() -> Vec<DmarcInternalReport> {
    let future = one_year_from_now();

    vec![
        // Report 1: Clean domain with all-pass records
        DmarcInternalReport {
            created_at: now(),
            deliver_at: future,
            domain: "trusted-sender.com".to_string(),
            policy_identifier: 100,
            report: DmarcReport {
                date_range_begin: days_ago(1),
                date_range_end: now(),
                email: "dmarc@myserver.com".to_string(),
                errors: Map::new(vec![]),
                extensions: List::from(vec![]),
                extra_contact_info: Some("https://myserver.com/dmarc".to_string()),
                org_name: "My Mail Server".to_string(),
                policy_adkim: DmarcAlignment::Relaxed,
                policy_aspf: DmarcAlignment::Relaxed,
                policy_disposition: DmarcDisposition::None,
                policy_domain: "trusted-sender.com".to_string(),
                policy_failure_reporting_options: Map::new(vec![]),
                policy_subdomain_disposition: DmarcDisposition::Quarantine,
                policy_testing_mode: false,
                policy_version: Some("DMARC1".to_string()),
                records: List::from(vec![DmarcReportRecord {
                    count: 500,
                    dkim_results: List::from(vec![DmarcDkimResult {
                        domain: "trusted-sender.com".to_string(),
                        human_result: None,
                        result: DkimAuthResult::Pass,
                        selector: "selector1".to_string(),
                    }]),
                    envelope_from: "trusted-sender.com".to_string(),
                    envelope_to: Some("myserver.com".to_string()),
                    evaluated_disposition: Default::default(),
                    evaluated_dkim: DmarcResult::Pass,
                    evaluated_spf: DmarcResult::Pass,
                    extensions: List::from(vec![]),
                    header_from: "trusted-sender.com".to_string(),
                    policy_override_reasons: List::from(vec![]),
                    source_ip: Some(IpAddr(std::net::IpAddr::V4(Ipv4Addr::new(
                        93, 184, 216, 34,
                    )))),
                    spf_results: List::from(vec![DmarcSpfResult {
                        domain: "trusted-sender.com".to_string(),
                        human_result: None,
                        result: SpfAuthResult::Pass,
                        scope: SpfDomainScope::MailFrom,
                    }]),
                }]),
                report_id: "dmarc-int-001".to_string(),
                version: Float::from(1.0),
            },
            rua: Map::new(vec!["mailto:dmarc-rua@trusted-sender.com".to_string()]),
        },
        // Report 2: Domain with DKIM failure and strict alignment
        DmarcInternalReport {
            created_at: now(),
            deliver_at: future,
            domain: "strict-domain.org".to_string(),
            policy_identifier: 200,
            report: DmarcReport {
                date_range_begin: days_ago(1),
                date_range_end: now(),
                email: "dmarc@myserver.com".to_string(),
                errors: Map::new(vec!["DKIM signature verification failed".to_string()]),
                extensions: List::from(vec![]),
                extra_contact_info: None,
                org_name: "My Mail Server".to_string(),
                policy_adkim: DmarcAlignment::Strict,
                policy_aspf: DmarcAlignment::Strict,
                policy_disposition: DmarcDisposition::Reject,
                policy_domain: "strict-domain.org".to_string(),
                policy_failure_reporting_options: Map::new(vec![]),
                policy_subdomain_disposition: DmarcDisposition::Reject,
                policy_testing_mode: false,
                policy_version: Some("DMARC1".to_string()),
                records: List::from(vec![DmarcReportRecord {
                    count: 12,
                    dkim_results: List::from(vec![DmarcDkimResult {
                        domain: "strict-domain.org".to_string(),
                        human_result: Some("signature verification failed".to_string()),
                        result: DkimAuthResult::Fail,
                        selector: "dkim2024".to_string(),
                    }]),
                    envelope_from: "strict-domain.org".to_string(),
                    envelope_to: None,
                    evaluated_disposition: Default::default(),
                    evaluated_dkim: DmarcResult::Fail,
                    evaluated_spf: DmarcResult::Pass,
                    extensions: List::from(vec![]),
                    header_from: "strict-domain.org".to_string(),
                    policy_override_reasons: List::from(vec![]),
                    source_ip: Some(IpAddr(std::net::IpAddr::V4(Ipv4Addr::new(
                        198, 51, 100, 50,
                    )))),
                    spf_results: List::from(vec![DmarcSpfResult {
                        domain: "strict-domain.org".to_string(),
                        human_result: None,
                        result: SpfAuthResult::Pass,
                        scope: SpfDomainScope::MailFrom,
                    }]),
                }]),
                report_id: "dmarc-int-002".to_string(),
                version: Float::from(1.0),
            },
            rua: Map::new(vec!["mailto:dmarc@strict-domain.org".to_string()]),
        },
        // Report 3: Domain in testing mode with multiple record types
        DmarcInternalReport {
            created_at: now(),
            deliver_at: future,
            domain: "new-policy.io".to_string(),
            policy_identifier: 300,
            report: DmarcReport {
                date_range_begin: days_ago(1),
                date_range_end: now(),
                email: "dmarc@myserver.com".to_string(),
                errors: Map::new(vec![]),
                extensions: List::from(vec![]),
                extra_contact_info: None,
                org_name: "My Mail Server".to_string(),
                policy_adkim: DmarcAlignment::Relaxed,
                policy_aspf: DmarcAlignment::Strict,
                policy_disposition: DmarcDisposition::Quarantine,
                policy_domain: "new-policy.io".to_string(),
                policy_failure_reporting_options: Map::new(vec![]),
                policy_subdomain_disposition: DmarcDisposition::None,
                policy_testing_mode: true,
                policy_version: Some("DMARC1".to_string()),
                records: List::from(vec![
                    DmarcReportRecord {
                        count: 200,
                        dkim_results: List::from(vec![DmarcDkimResult {
                            domain: "new-policy.io".to_string(),
                            human_result: None,
                            result: DkimAuthResult::Pass,
                            selector: "sel1".to_string(),
                        }]),
                        envelope_from: "new-policy.io".to_string(),
                        envelope_to: Some("myserver.com".to_string()),
                        evaluated_disposition: Default::default(),
                        evaluated_dkim: DmarcResult::Pass,
                        evaluated_spf: DmarcResult::Pass,
                        extensions: List::from(vec![]),
                        header_from: "new-policy.io".to_string(),
                        policy_override_reasons: List::from(vec![]),
                        source_ip: Some(IpAddr(std::net::IpAddr::V4(Ipv4Addr::new(
                            203, 0, 113, 5,
                        )))),
                        spf_results: List::from(vec![DmarcSpfResult {
                            domain: "new-policy.io".to_string(),
                            human_result: None,
                            result: SpfAuthResult::Pass,
                            scope: SpfDomainScope::MailFrom,
                        }]),
                    },
                    DmarcReportRecord {
                        count: 3,
                        dkim_results: List::from(vec![DmarcDkimResult {
                            domain: "new-policy.io".to_string(),
                            human_result: Some("no signature found".to_string()),
                            result: DkimAuthResult::None,
                            selector: "".to_string(),
                        }]),
                        envelope_from: "spoofed.example".to_string(),
                        envelope_to: Some("myserver.com".to_string()),
                        evaluated_disposition: Default::default(),
                        evaluated_dkim: DmarcResult::Fail,
                        evaluated_spf: DmarcResult::Fail,
                        extensions: List::from(vec![]),
                        header_from: "new-policy.io".to_string(),
                        policy_override_reasons: List::from(vec![]),
                        source_ip: Some(IpAddr(std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99)))),
                        spf_results: List::from(vec![DmarcSpfResult {
                            domain: "spoofed.example".to_string(),
                            human_result: Some("SPF record not found".to_string()),
                            result: SpfAuthResult::None,
                            scope: SpfDomainScope::MailFrom,
                        }]),
                    },
                ]),
                report_id: "dmarc-int-003".to_string(),
                version: Float::from(1.0),
            },
            rua: Map::new(vec![
                "mailto:dmarc@new-policy.io".to_string(),
                "mailto:dmarc-backup@new-policy.io".to_string(),
            ]),
        },
    ]
}

fn sample_tls_external_reports() -> Vec<TlsExternalReport> {
    let future = one_year_from_now();

    vec![
        // Report 1: Clean report from a large provider
        TlsExternalReport {
            expires_at: future,
            from: "tls-reports@bigprovider.com".to_string(),
            member_tenant_id: None,
            received_at: now(),
            report: TlsReport {
                contact_info: Some("postmaster@bigprovider.com".to_string()),
                date_range_end: now(),
                date_range_start: days_ago(1),
                organization_name: Some("Big Provider Inc.".to_string()),
                policies: List::from(vec![
                    TlsReportPolicy {
                        failure_details: List::from(vec![]),
                        mx_hosts: Map::new(vec![
                            "mx1.myserver.com".to_string(),
                            "mx2.myserver.com".to_string(),
                        ]),
                        policy_domain: "myserver.com".to_string(),
                        policy_strings: Map::new(vec![
                            "mode: enforce".to_string(),
                            "max_age: 604800".to_string(),
                        ]),
                        policy_type: TlsPolicyType::Sts,
                        total_failed_sessions: 0,
                        total_successful_sessions: 12500,
                    },
                    TlsReportPolicy {
                        failure_details: List::from(vec![]),
                        mx_hosts: Map::new(vec!["mx3.myserver.com".to_string()]),
                        policy_domain: "myserver.com".to_string(),
                        policy_strings: Map::new(vec![]),
                        policy_type: TlsPolicyType::Tlsa,
                        total_failed_sessions: 0,
                        total_successful_sessions: 3200,
                    },
                    TlsReportPolicy {
                        failure_details: List::from(vec![TlsFailureDetails {
                            additional_information: Some(
                                "Fallback to plaintext after STARTTLS failure".to_string(),
                            ),
                            failed_session_count: 2,
                            failure_reason_code: Some("starttls-not-supported".to_string()),
                            receiving_ip: Some(IpAddr(std::net::IpAddr::V4(Ipv4Addr::new(
                                192, 0, 2, 50,
                            )))),
                            receiving_mx_helo: Some("backup-mx.myserver.com".to_string()),
                            receiving_mx_hostname: Some("backup-mx.myserver.com".to_string()),
                            result_type: TlsResultType::StartTlsNotSupported,
                            sending_mta_ip: Some(IpAddr(std::net::IpAddr::V4(Ipv4Addr::new(
                                198, 51, 100, 5,
                            )))),
                        }]),
                        mx_hosts: Map::new(vec!["backup-mx.myserver.com".to_string()]),
                        policy_domain: "myserver.com".to_string(),
                        policy_strings: Map::new(vec!["mode: testing".to_string()]),
                        policy_type: TlsPolicyType::Sts,
                        total_failed_sessions: 2,
                        total_successful_sessions: 50,
                    },
                ]),
                report_id: "tls-ext-001-bigprovider".to_string(),
            },
            subject: "TLS-RPT report for myserver.com".to_string(),
            to: Map::new(vec!["tls-rpt@myserver.com".to_string()]),
        },
        // Report 2: Report with expired certificate failures
        TlsExternalReport {
            expires_at: future,
            from: "noreply@securemail.org".to_string(),
            member_tenant_id: None,
            received_at: now(),
            report: TlsReport {
                contact_info: None,
                date_range_end: now(),
                date_range_start: days_ago(1),
                organization_name: Some("SecureMail".to_string()),
                policies: List::from(vec![
                    TlsReportPolicy {
                        failure_details: List::from(vec![TlsFailureDetails {
                            additional_information: Some(
                                "Certificate expired 2 days ago".to_string(),
                            ),
                            failed_session_count: 30,
                            failure_reason_code: Some("certificate-expired".to_string()),
                            receiving_ip: Some(IpAddr(std::net::IpAddr::V4(Ipv4Addr::new(
                                192, 0, 2, 10,
                            )))),
                            receiving_mx_helo: Some("mx1.myserver.com".to_string()),
                            receiving_mx_hostname: Some("mx1.myserver.com".to_string()),
                            result_type: TlsResultType::CertificateExpired,
                            sending_mta_ip: Some(IpAddr(std::net::IpAddr::V4(Ipv4Addr::new(
                                198, 51, 100, 1,
                            )))),
                        }]),
                        mx_hosts: Map::new(vec!["mx1.myserver.com".to_string()]),
                        policy_domain: "myserver.com".to_string(),
                        policy_strings: Map::new(vec!["mode: enforce".to_string()]),
                        policy_type: TlsPolicyType::Sts,
                        total_failed_sessions: 30,
                        total_successful_sessions: 70,
                    },
                    TlsReportPolicy {
                        failure_details: List::from(vec![TlsFailureDetails {
                            additional_information: Some(
                                "CN=old.myserver.com does not match mx2.myserver.com".to_string(),
                            ),
                            failed_session_count: 15,
                            failure_reason_code: Some("certificate-host-mismatch".to_string()),
                            receiving_ip: Some(IpAddr(std::net::IpAddr::V4(Ipv4Addr::new(
                                192, 0, 2, 11,
                            )))),
                            receiving_mx_helo: Some("mx2.myserver.com".to_string()),
                            receiving_mx_hostname: Some("mx2.myserver.com".to_string()),
                            result_type: TlsResultType::CertificateHostMismatch,
                            sending_mta_ip: Some(IpAddr(std::net::IpAddr::V4(Ipv4Addr::new(
                                198, 51, 100, 2,
                            )))),
                        }]),
                        mx_hosts: Map::new(vec!["mx2.myserver.com".to_string()]),
                        policy_domain: "myserver.com".to_string(),
                        policy_strings: Map::new(vec!["mode: enforce".to_string()]),
                        policy_type: TlsPolicyType::Sts,
                        total_failed_sessions: 15,
                        total_successful_sessions: 85,
                    },
                    TlsReportPolicy {
                        failure_details: List::from(vec![TlsFailureDetails {
                            additional_information: Some(
                                "Untrusted CA in certificate chain".to_string(),
                            ),
                            failed_session_count: 8,
                            failure_reason_code: Some("certificate-not-trusted".to_string()),
                            receiving_ip: Some(IpAddr(std::net::IpAddr::V4(Ipv4Addr::new(
                                192, 0, 2, 12,
                            )))),
                            receiving_mx_helo: Some("mx3.myserver.com".to_string()),
                            receiving_mx_hostname: Some("mx3.myserver.com".to_string()),
                            result_type: TlsResultType::CertificateNotTrusted,
                            sending_mta_ip: Some(IpAddr(std::net::IpAddr::V4(Ipv4Addr::new(
                                198, 51, 100, 3,
                            )))),
                        }]),
                        mx_hosts: Map::new(vec!["mx3.myserver.com".to_string()]),
                        policy_domain: "myserver.com".to_string(),
                        policy_strings: Map::new(vec!["mode: testing".to_string()]),
                        policy_type: TlsPolicyType::Sts,
                        total_failed_sessions: 8,
                        total_successful_sessions: 120,
                    },
                ]),
                report_id: "tls-ext-002-securemail".to_string(),
            },
            subject: "SMTP TLS Reporting for myserver.com".to_string(),
            to: Map::new(vec!["tls-rpt@myserver.com".to_string()]),
        },
        // Report 3: DANE report with no policy found
        TlsExternalReport {
            expires_at: future,
            from: "reports@mailhoster.net".to_string(),
            member_tenant_id: None,
            received_at: now(),
            report: TlsReport {
                contact_info: Some("abuse@mailhoster.net".to_string()),
                date_range_end: now(),
                date_range_start: days_ago(7),
                organization_name: Some("MailHoster".to_string()),
                policies: List::from(vec![
                    TlsReportPolicy {
                        failure_details: List::from(vec![TlsFailureDetails {
                            additional_information: None,
                            failed_session_count: 10,
                            failure_reason_code: None,
                            receiving_ip: Some(IpAddr(std::net::IpAddr::V4(Ipv4Addr::new(
                                203, 0, 113, 25,
                            )))),
                            receiving_mx_helo: Some("mx2.myserver.com".to_string()),
                            receiving_mx_hostname: Some("mx2.myserver.com".to_string()),
                            result_type: TlsResultType::StartTlsNotSupported,
                            sending_mta_ip: Some(IpAddr(std::net::IpAddr::V4(Ipv4Addr::new(
                                203, 0, 113, 50,
                            )))),
                        }]),
                        mx_hosts: Map::new(vec!["mx2.myserver.com".to_string()]),
                        policy_domain: "myserver.com".to_string(),
                        policy_strings: Map::new(vec![]),
                        policy_type: TlsPolicyType::NoPolicyFound,
                        total_failed_sessions: 10,
                        total_successful_sessions: 0,
                    },
                    TlsReportPolicy {
                        failure_details: List::from(vec![TlsFailureDetails {
                            additional_information: Some(
                                "DANE TLSA record invalid for mx1.myserver.com".to_string(),
                            ),
                            failed_session_count: 20,
                            failure_reason_code: Some("tlsa-invalid".to_string()),
                            receiving_ip: Some(IpAddr(std::net::IpAddr::V4(Ipv4Addr::new(
                                203, 0, 113, 26,
                            )))),
                            receiving_mx_helo: Some("mx1.myserver.com".to_string()),
                            receiving_mx_hostname: Some("mx1.myserver.com".to_string()),
                            result_type: TlsResultType::TlsaInvalid,
                            sending_mta_ip: Some(IpAddr(std::net::IpAddr::V4(Ipv4Addr::new(
                                203, 0, 113, 51,
                            )))),
                        }]),
                        mx_hosts: Map::new(vec!["mx1.myserver.com".to_string()]),
                        policy_domain: "myserver.com".to_string(),
                        policy_strings: Map::new(vec![]),
                        policy_type: TlsPolicyType::Tlsa,
                        total_failed_sessions: 20,
                        total_successful_sessions: 180,
                    },
                    TlsReportPolicy {
                        failure_details: List::from(vec![TlsFailureDetails {
                            additional_information: Some(
                                "DNSSEC validation failed for _25._tcp.mx1.myserver.com"
                                    .to_string(),
                            ),
                            failed_session_count: 5,
                            failure_reason_code: Some("dnssec-invalid".to_string()),
                            receiving_ip: Some(IpAddr(std::net::IpAddr::V4(Ipv4Addr::new(
                                203, 0, 113, 27,
                            )))),
                            receiving_mx_helo: Some("mx1.myserver.com".to_string()),
                            receiving_mx_hostname: Some("mx1.myserver.com".to_string()),
                            result_type: TlsResultType::DnssecInvalid,
                            sending_mta_ip: Some(IpAddr(std::net::IpAddr::V4(Ipv4Addr::new(
                                203, 0, 113, 52,
                            )))),
                        }]),
                        mx_hosts: Map::new(vec!["mx1.myserver.com".to_string()]),
                        policy_domain: "myserver.com".to_string(),
                        policy_strings: Map::new(vec![]),
                        policy_type: TlsPolicyType::Tlsa,
                        total_failed_sessions: 5,
                        total_successful_sessions: 95,
                    },
                ]),
                report_id: "tls-ext-003-mailhoster".to_string(),
            },
            subject: "TLS Report: myserver.com".to_string(),
            to: Map::new(vec!["tls-rpt@myserver.com".to_string()]),
        },
    ]
}

fn sample_dmarc_external_reports() -> Vec<DmarcExternalReport> {
    let future = one_year_from_now();

    vec![
        // Report 1: Google-style aggregate report, all pass
        DmarcExternalReport {
            expires_at: future,
            from: "noreply-dmarc@google.com".to_string(),
            member_tenant_id: None,
            received_at: now(),
            report: DmarcReport {
                date_range_begin: days_ago(1),
                date_range_end: now(),
                email: "noreply-dmarc@google.com".to_string(),
                errors: Map::new(vec![]),
                extensions: List::from(vec![]),
                extra_contact_info: Some(
                    "https://support.google.com/a/answer/10032169".to_string(),
                ),
                org_name: "google.com".to_string(),
                policy_adkim: DmarcAlignment::Relaxed,
                policy_aspf: DmarcAlignment::Relaxed,
                policy_disposition: DmarcDisposition::None,
                policy_domain: "myserver.com".to_string(),
                policy_failure_reporting_options: Map::new(vec![]),
                policy_subdomain_disposition: DmarcDisposition::None,
                policy_testing_mode: false,
                policy_version: Some("DMARC1".to_string()),
                records: List::from(vec![
                    DmarcReportRecord {
                        count: 1500,
                        dkim_results: List::from(vec![DmarcDkimResult {
                            domain: "myserver.com".to_string(),
                            human_result: None,
                            result: DkimAuthResult::Pass,
                            selector: "google".to_string(),
                        }]),
                        envelope_from: "myserver.com".to_string(),
                        envelope_to: None,
                        evaluated_disposition: Default::default(),
                        evaluated_dkim: DmarcResult::Pass,
                        evaluated_spf: DmarcResult::Pass,
                        extensions: List::from(vec![]),
                        header_from: "myserver.com".to_string(),
                        policy_override_reasons: List::from(vec![]),
                        source_ip: Some(IpAddr(std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))),
                        spf_results: List::from(vec![DmarcSpfResult {
                            domain: "myserver.com".to_string(),
                            human_result: None,
                            result: SpfAuthResult::Pass,
                            scope: SpfDomainScope::MailFrom,
                        }]),
                    },
                    DmarcReportRecord {
                        count: 320,
                        dkim_results: List::from(vec![DmarcDkimResult {
                            domain: "myserver.com".to_string(),
                            human_result: None,
                            result: DkimAuthResult::Pass,
                            selector: "selector2".to_string(),
                        }]),
                        envelope_from: "myserver.com".to_string(),
                        envelope_to: None,
                        evaluated_disposition: Default::default(),
                        evaluated_dkim: DmarcResult::Pass,
                        evaluated_spf: DmarcResult::Pass,
                        extensions: List::from(vec![]),
                        header_from: "myserver.com".to_string(),
                        policy_override_reasons: List::from(vec![]),
                        source_ip: Some(IpAddr(std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)))),
                        spf_results: List::from(vec![DmarcSpfResult {
                            domain: "myserver.com".to_string(),
                            human_result: None,
                            result: SpfAuthResult::Pass,
                            scope: SpfDomainScope::MailFrom,
                        }]),
                    },
                    DmarcReportRecord {
                        count: 7,
                        dkim_results: List::from(vec![DmarcDkimResult {
                            domain: "sub.myserver.com".to_string(),
                            human_result: Some("DKIM signature uses subdomain".to_string()),
                            result: DkimAuthResult::Pass,
                            selector: "google".to_string(),
                        }]),
                        envelope_from: "sub.myserver.com".to_string(),
                        envelope_to: None,
                        evaluated_disposition: Default::default(),
                        evaluated_dkim: DmarcResult::Pass,
                        evaluated_spf: DmarcResult::Fail,
                        extensions: List::from(vec![]),
                        header_from: "myserver.com".to_string(),
                        policy_override_reasons: List::from(vec![]),
                        source_ip: Some(IpAddr(std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3)))),
                        spf_results: List::from(vec![DmarcSpfResult {
                            domain: "sub.myserver.com".to_string(),
                            human_result: Some(
                                "SPF alignment failed: subdomain mismatch".to_string(),
                            ),
                            result: SpfAuthResult::SoftFail,
                            scope: SpfDomainScope::MailFrom,
                        }]),
                    },
                ]),
                report_id: "dmarc-ext-001-google".to_string(),
                version: Float::from(1.0),
            },
            subject: "Report domain: myserver.com Submitter: google.com".to_string(),
            to: Map::new(vec!["dmarc-rua@myserver.com".to_string()]),
        },
        // Report 2: Report showing spoofing attempts from an unknown source
        DmarcExternalReport {
            expires_at: future,
            from: "dmarc@yahoo.com".to_string(),
            member_tenant_id: None,
            received_at: now(),
            report: DmarcReport {
                date_range_begin: days_ago(1),
                date_range_end: now(),
                email: "dmarc@yahoo.com".to_string(),
                errors: Map::new(vec![]),
                extensions: List::from(vec![]),
                extra_contact_info: None,
                org_name: "Yahoo! Inc.".to_string(),
                policy_adkim: DmarcAlignment::Strict,
                policy_aspf: DmarcAlignment::Strict,
                policy_disposition: DmarcDisposition::Reject,
                policy_domain: "myserver.com".to_string(),
                policy_failure_reporting_options: Map::new(vec![]),
                policy_subdomain_disposition: DmarcDisposition::Reject,
                policy_testing_mode: false,
                policy_version: Some("DMARC1".to_string()),
                records: List::from(vec![
                    DmarcReportRecord {
                        count: 8,
                        dkim_results: List::from(vec![DmarcDkimResult {
                            domain: "myserver.com".to_string(),
                            human_result: Some("bad signature".to_string()),
                            result: DkimAuthResult::Fail,
                            selector: "default".to_string(),
                        }]),
                        envelope_from: "attacker.example".to_string(),
                        envelope_to: None,
                        evaluated_disposition: Default::default(),
                        evaluated_dkim: DmarcResult::Fail,
                        evaluated_spf: DmarcResult::Fail,
                        extensions: List::from(vec![]),
                        header_from: "myserver.com".to_string(),
                        policy_override_reasons: List::from(vec![]),
                        source_ip: Some(IpAddr(std::net::IpAddr::V4(Ipv4Addr::new(
                            198, 51, 100, 222,
                        )))),
                        spf_results: List::from(vec![DmarcSpfResult {
                            domain: "attacker.example".to_string(),
                            human_result: Some("domain not found".to_string()),
                            result: SpfAuthResult::Fail,
                            scope: SpfDomainScope::MailFrom,
                        }]),
                    },
                    DmarcReportRecord {
                        count: 15,
                        dkim_results: List::from(vec![DmarcDkimResult {
                            domain: "phisher.net".to_string(),
                            human_result: Some(
                                "no valid DKIM signature for myserver.com".to_string(),
                            ),
                            result: DkimAuthResult::None,
                            selector: "".to_string(),
                        }]),
                        envelope_from: "phisher.net".to_string(),
                        envelope_to: None,
                        evaluated_disposition: Default::default(),
                        evaluated_dkim: DmarcResult::Fail,
                        evaluated_spf: DmarcResult::Fail,
                        extensions: List::from(vec![]),
                        header_from: "myserver.com".to_string(),
                        policy_override_reasons: List::from(vec![]),
                        source_ip: Some(IpAddr(std::net::IpAddr::V4(Ipv4Addr::new(
                            198, 51, 100, 100,
                        )))),
                        spf_results: List::from(vec![DmarcSpfResult {
                            domain: "phisher.net".to_string(),
                            human_result: Some("SPF domain mismatch".to_string()),
                            result: SpfAuthResult::Fail,
                            scope: SpfDomainScope::MailFrom,
                        }]),
                    },
                    DmarcReportRecord {
                        count: 2,
                        dkim_results: List::from(vec![
                            DmarcDkimResult {
                                domain: "myserver.com".to_string(),
                                human_result: Some("signature expired".to_string()),
                                result: DkimAuthResult::Fail,
                                selector: "selector1".to_string(),
                            },
                            DmarcDkimResult {
                                domain: "myserver.com".to_string(),
                                human_result: Some("body hash mismatch".to_string()),
                                result: DkimAuthResult::Fail,
                                selector: "selector2".to_string(),
                            },
                        ]),
                        envelope_from: "compromised-relay.example".to_string(),
                        envelope_to: None,
                        evaluated_disposition: Default::default(),
                        evaluated_dkim: DmarcResult::Fail,
                        evaluated_spf: DmarcResult::Fail,
                        extensions: List::from(vec![]),
                        header_from: "myserver.com".to_string(),
                        policy_override_reasons: List::from(vec![]),
                        source_ip: Some(IpAddr(std::net::IpAddr::V4(Ipv4Addr::new(
                            198, 51, 100, 33,
                        )))),
                        spf_results: List::from(vec![DmarcSpfResult {
                            domain: "compromised-relay.example".to_string(),
                            human_result: None,
                            result: SpfAuthResult::PermError,
                            scope: SpfDomainScope::MailFrom,
                        }]),
                    },
                ]),
                report_id: "dmarc-ext-002-yahoo".to_string(),
                version: Float::from(1.0),
            },
            subject: "Report domain: myserver.com Submitter: yahoo.com".to_string(),
            to: Map::new(vec!["dmarc-rua@myserver.com".to_string()]),
        },
        // Report 3: Microsoft report with forwarded mail override
        DmarcExternalReport {
            expires_at: future,
            from: "dmarc-noreply@microsoft.com".to_string(),
            member_tenant_id: None,
            received_at: now(),
            report: DmarcReport {
                date_range_begin: days_ago(1),
                date_range_end: now(),
                email: "dmarc-noreply@microsoft.com".to_string(),
                errors: Map::new(vec![]),
                extensions: List::from(vec![]),
                extra_contact_info: None,
                org_name: "Microsoft Corporation".to_string(),
                policy_adkim: DmarcAlignment::Relaxed,
                policy_aspf: DmarcAlignment::Relaxed,
                policy_disposition: DmarcDisposition::Quarantine,
                policy_domain: "myserver.com".to_string(),
                policy_failure_reporting_options: Map::new(vec![]),
                policy_subdomain_disposition: DmarcDisposition::Quarantine,
                policy_testing_mode: false,
                policy_version: Some("DMARC1".to_string()),
                records: List::from(vec![
                    DmarcReportRecord {
                        count: 25,
                        dkim_results: List::from(vec![DmarcDkimResult {
                            domain: "myserver.com".to_string(),
                            human_result: None,
                            result: DkimAuthResult::Pass,
                            selector: "selector1".to_string(),
                        }]),
                        envelope_from: "forwarder.example.com".to_string(),
                        envelope_to: None,
                        evaluated_disposition: Default::default(),
                        evaluated_dkim: DmarcResult::Pass,
                        evaluated_spf: DmarcResult::Fail,
                        extensions: List::from(vec![]),
                        header_from: "myserver.com".to_string(),
                        policy_override_reasons: List::from(vec![]),
                        source_ip: Some(IpAddr(std::net::IpAddr::V4(Ipv4Addr::new(
                            203, 0, 113, 100,
                        )))),
                        spf_results: List::from(vec![DmarcSpfResult {
                            domain: "forwarder.example.com".to_string(),
                            human_result: None,
                            result: SpfAuthResult::SoftFail,
                            scope: SpfDomainScope::MailFrom,
                        }]),
                    },
                    DmarcReportRecord {
                        count: 800,
                        dkim_results: List::from(vec![DmarcDkimResult {
                            domain: "myserver.com".to_string(),
                            human_result: None,
                            result: DkimAuthResult::Pass,
                            selector: "selector1".to_string(),
                        }]),
                        envelope_from: "myserver.com".to_string(),
                        envelope_to: None,
                        evaluated_disposition: Default::default(),
                        evaluated_dkim: DmarcResult::Pass,
                        evaluated_spf: DmarcResult::Pass,
                        extensions: List::from(vec![]),
                        header_from: "myserver.com".to_string(),
                        policy_override_reasons: List::from(vec![]),
                        source_ip: Some(IpAddr(std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))),
                        spf_results: List::from(vec![DmarcSpfResult {
                            domain: "myserver.com".to_string(),
                            human_result: None,
                            result: SpfAuthResult::Pass,
                            scope: SpfDomainScope::MailFrom,
                        }]),
                    },
                    DmarcReportRecord {
                        count: 40,
                        dkim_results: List::from(vec![DmarcDkimResult {
                            domain: "myserver.com".to_string(),
                            human_result: Some(
                                "DKIM signature OK but SPF failed via mailing list".to_string(),
                            ),
                            result: DkimAuthResult::Pass,
                            selector: "selector1".to_string(),
                        }]),
                        envelope_from: "mailinglist.example.org".to_string(),
                        envelope_to: None,
                        evaluated_disposition: Default::default(),
                        evaluated_dkim: DmarcResult::Pass,
                        evaluated_spf: DmarcResult::Fail,
                        extensions: List::from(vec![]),
                        header_from: "myserver.com".to_string(),
                        policy_override_reasons: List::from(vec![]),
                        source_ip: Some(IpAddr(std::net::IpAddr::V4(Ipv4Addr::new(
                            203, 0, 113, 200,
                        )))),
                        spf_results: List::from(vec![DmarcSpfResult {
                            domain: "mailinglist.example.org".to_string(),
                            human_result: Some("Mailing list rewrite".to_string()),
                            result: SpfAuthResult::Fail,
                            scope: SpfDomainScope::MailFrom,
                        }]),
                    },
                ]),
                report_id: "dmarc-ext-003-msft".to_string(),
                version: Float::from(1.0),
            },
            subject: "Report domain: myserver.com Submitter: microsoft.com".to_string(),
            to: Map::new(vec!["dmarc-rua@myserver.com".to_string()]),
        },
    ]
}

fn sample_arf_external_reports() -> Vec<ArfExternalReport> {
    let future = one_year_from_now();

    vec![
        // Report 1: Abuse complaint from a user
        ArfExternalReport {
            expires_at: future,
            from: "fbl@isp-provider.com".to_string(),
            member_tenant_id: None,
            received_at: now(),
            report: ArfFeedbackReport {
                arrival_date: Some(days_ago(1)),
                auth_failure: ArfAuthFailureType::Unspecified,
                authentication_results: Map::new(vec![
                    "dkim=pass header.d=myserver.com".to_string(),
                    "spf=pass smtp.mailfrom=myserver.com".to_string(),
                ]),
                delivery_result: ArfDeliveryResult::Delivered,
                dkim_adsp_dns: None,
                dkim_canonicalized_body: None,
                dkim_canonicalized_header: None,
                dkim_domain: Some("myserver.com".to_string()),
                dkim_identity: None,
                dkim_selector: Some("selector1".to_string()),
                dkim_selector_dns: None,
                feedback_type: ArfFeedbackType::Abuse,
                headers: Some(
                    "From: newsletter@myserver.com\r\nTo: user@isp-provider.com\r\nSubject: Weekly Newsletter\r\nDate: Mon, 10 Apr 2027 10:00:00 +0000"
                        .to_string(),
                ),
                identity_alignment: ArfIdentityAlignment::DkimSpf,
                incidents: 1,
                message: Some("User marked this message as spam".to_string()),
                original_envelope_id: Some("env-newsletter-001".to_string()),
                original_mail_from: Some("newsletter@myserver.com".to_string()),
                original_rcpt_to: Some("user@isp-provider.com".to_string()),
                reported_domains: Map::new(vec!["myserver.com".to_string()]),
                reported_uris: Map::new(vec![]),
                reporting_mta: Some("fbl.isp-provider.com".to_string()),
                source_ip: Some(IpAddr(std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))),
                source_port: Some(25),
                spf_dns: None,
                user_agent: Some("ISP-FBL/2.0".to_string()),
                version: 1,
            },
            subject: "FBL report from isp-provider.com".to_string(),
            to: Map::new(vec!["abuse@myserver.com".to_string()]),
        },
        // Report 2: Auth failure report (DKIM)
        ArfExternalReport {
            expires_at: future,
            from: "authfail@receiver.org".to_string(),
            member_tenant_id: None,
            received_at: now(),
            report: ArfFeedbackReport {
                arrival_date: Some(days_ago(2)),
                auth_failure: ArfAuthFailureType::Signature,
                authentication_results: Map::new(vec![
                    "dkim=fail header.d=myserver.com".to_string(),
                ]),
                delivery_result: ArfDeliveryResult::Reject,
                dkim_adsp_dns: None,
                dkim_canonicalized_body: Some("base64bodyhash==".to_string()),
                dkim_canonicalized_header: Some("base64headerhash==".to_string()),
                dkim_domain: Some("myserver.com".to_string()),
                dkim_identity: Some("@myserver.com".to_string()),
                dkim_selector: Some("selector1".to_string()),
                dkim_selector_dns: Some(
                    "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUA".to_string(),
                ),
                feedback_type: ArfFeedbackType::AuthFailure,
                headers: Some(
                    "From: info@myserver.com\r\nTo: contact@receiver.org\r\nSubject: Important Update"
                        .to_string(),
                ),
                identity_alignment: ArfIdentityAlignment::None,
                incidents: 3,
                message: None,
                original_envelope_id: None,
                original_mail_from: Some("info@myserver.com".to_string()),
                original_rcpt_to: Some("contact@receiver.org".to_string()),
                reported_domains: Map::new(vec!["myserver.com".to_string()]),
                reported_uris: Map::new(vec![]),
                reporting_mta: Some("mx.receiver.org".to_string()),
                source_ip: Some(IpAddr(std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))),
                source_port: Some(587),
                spf_dns: None,
                user_agent: Some("ReceiverMTA/1.0".to_string()),
                version: 1,
            },
            subject: "Authentication failure report for myserver.com".to_string(),
            to: Map::new(vec!["abuse@myserver.com".to_string()]),
        },
        // Report 3: Fraud/phishing report
        ArfExternalReport {
            expires_at: future,
            from: "reports@antiphish.net".to_string(),
            member_tenant_id: None,
            received_at: now(),
            report: ArfFeedbackReport {
                arrival_date: Some(days_ago(3)),
                auth_failure: ArfAuthFailureType::Dmarc,
                authentication_results: Map::new(vec![
                    "dmarc=fail header.from=myserver.com".to_string(),
                    "spf=fail smtp.mailfrom=spoofed.example".to_string(),
                ]),
                delivery_result: ArfDeliveryResult::Policy,
                dkim_adsp_dns: None,
                dkim_canonicalized_body: None,
                dkim_canonicalized_header: None,
                dkim_domain: None,
                dkim_identity: None,
                dkim_selector: None,
                dkim_selector_dns: None,
                feedback_type: ArfFeedbackType::Fraud,
                headers: Some(
                    "From: security@myserver.com\r\nTo: victim@antiphish.net\r\nSubject: Urgent: Verify your account"
                        .to_string(),
                ),
                identity_alignment: ArfIdentityAlignment::None,
                incidents: 50,
                message: Some("Phishing attempt impersonating myserver.com".to_string()),
                original_envelope_id: None,
                original_mail_from: Some("spoofer@spoofed.example".to_string()),
                original_rcpt_to: Some("victim@antiphish.net".to_string()),
                reported_domains: Map::new(vec![
                    "myserver.com".to_string(),
                    "spoofed.example".to_string(),
                ]),
                reported_uris: Map::new(vec![
                    "https://evil-site.example/phish".to_string(),
                ]),
                reporting_mta: Some("gateway.antiphish.net".to_string()),
                source_ip: Some(IpAddr(std::net::IpAddr::V4(Ipv4Addr::new(
                    198, 51, 100, 77,
                )))),
                source_port: Some(25),
                spf_dns: Some("v=spf1 -all".to_string()),
                user_agent: Some("AntiPhish/3.0".to_string()),
                version: 1,
            },
            subject: "Fraud report: phishing attempt using myserver.com".to_string(),
            to: Map::new(vec![
                "abuse@myserver.com".to_string(),
                "security@myserver.com".to_string(),
            ]),
        },
    ]
}

fn one_year_from_now_u64() -> u64 {
    store::write::now() + 365 * 24 * 3600
}

fn one_year_from_now() -> UTCDateTime {
    UTCDateTime::from_timestamp(store::write::now().cast_signed() + 365 * 24 * 3600)
}

fn now() -> UTCDateTime {
    UTCDateTime::from_timestamp(store::write::now().cast_signed())
}

fn days_ago(days: i64) -> UTCDateTime {
    UTCDateTime::from_timestamp(store::write::now().cast_signed() - days * 24 * 3600)
}
