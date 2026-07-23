/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::server::TestServerBuilder;
use ::smtp::outbound::NextHop;
use common::config::smtp::{
    queue::{MxConfig, QueueExpiry, QueueName},
    report::AggregateFrequency,
    resolver::{Mode, MxPattern, Policy},
};
use mail_auth::{DnssecStatus, IpLookupStrategy, MX, RecordSet};
use mail_parser::DateTime;
use registry::{
    schema::{
        enums::MtaIpStrategy,
        structs::{
            Expression, MtaConnectionIpHost, MtaConnectionStrategy, MtaOutboundStrategy, MtaRoute,
            MtaRouteMx,
        },
    },
    types::{ipaddr::IpAddr, list::List},
};
use smtp::{
    outbound::{
        lookup::{SourceIp, ToNextHop},
        mta_sts::parse::ParsePolicy,
    },
    queue::{
        Error, ErrorDetails, FROM_AUTHENTICATED, Message, QueueEnvelope, Recipient, Schedule,
        Status,
    },
    reporting::AggregateTimestamp,
};
use std::{str::FromStr, sync::Arc};
use store::write::now;

#[tokio::test]
async fn strategies() {
    let ipv6: [IpAddr; 4] = [
        "a:b::1".parse().unwrap(),
        "a:b::2".parse().unwrap(),
        "a:b::3".parse().unwrap(),
        "a:b::4".parse().unwrap(),
    ];
    let ipv4: [IpAddr; 4] = [
        "10.0.0.1".parse().unwrap(),
        "10.0.0.2".parse().unwrap(),
        "10.0.0.3".parse().unwrap(),
        "10.0.0.4".parse().unwrap(),
    ];
    let ipv4_hosts = [
        "test1.example.com".to_string(),
        "test2.example.com".to_string(),
        "test3.example.com".to_string(),
        "test4.example.com".to_string(),
    ];
    let ipv6_hosts = [
        "test5.example.com".to_string(),
        "test6.example.com".to_string(),
        "test7.example.com".to_string(),
        "test8.example.com".to_string(),
    ];

    let mut test = TestServerBuilder::new("smtp_strategies_test")
        .await
        .with_http_listener(19016)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;

    // Add test settings
    let admin = test.account("admin");
    admin.mta_no_auth().await;
    admin
        .registry_create_object(MtaConnectionStrategy {
            name: "test".into(),
            ehlo_hostname: "test.example.com".to_string().into(),
            connect_timeout: 10_000u64.into(),
            source_ips: List::from_iter([
                MtaConnectionIpHost {
                    ehlo_hostname: "test1.example.com".to_string().into(),
                    source_ip: IpAddr::from_str("10.0.0.1").unwrap(),
                },
                MtaConnectionIpHost {
                    ehlo_hostname: "test2.example.com".to_string().into(),
                    source_ip: IpAddr::from_str("10.0.0.2").unwrap(),
                },
                MtaConnectionIpHost {
                    ehlo_hostname: "test3.example.com".to_string().into(),
                    source_ip: IpAddr::from_str("10.0.0.3").unwrap(),
                },
                MtaConnectionIpHost {
                    ehlo_hostname: "test4.example.com".to_string().into(),
                    source_ip: IpAddr::from_str("10.0.0.4").unwrap(),
                },
                MtaConnectionIpHost {
                    ehlo_hostname: "test5.example.com".to_string().into(),
                    source_ip: IpAddr::from_str("a:b::1").unwrap(),
                },
                MtaConnectionIpHost {
                    ehlo_hostname: "test6.example.com".to_string().into(),
                    source_ip: IpAddr::from_str("a:b::2").unwrap(),
                },
                MtaConnectionIpHost {
                    ehlo_hostname: "test7.example.com".to_string().into(),
                    source_ip: IpAddr::from_str("a:b::3").unwrap(),
                },
                MtaConnectionIpHost {
                    ehlo_hostname: "test8.example.com".to_string().into(),
                    source_ip: IpAddr::from_str("a:b::4").unwrap(),
                },
            ]),
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(MtaRoute::Mx(MtaRouteMx {
            ip_lookup_strategy: MtaIpStrategy::V4ThenV6,
            name: "test-v4".into(),
            ..Default::default()
        }))
        .await;
    admin
        .registry_create_object(MtaRoute::Mx(MtaRouteMx {
            ip_lookup_strategy: MtaIpStrategy::V6ThenV4,
            name: "test-v6".into(),
            ..Default::default()
        }))
        .await;
    admin
        .registry_create_object(MtaOutboundStrategy {
            schedule: Expression {
                else_: concat!(
                    "source + ' ' + received_from_ip + ' ' + ",
                    "received_via_port + ' ' + queue_name + ' ' + ",
                    "last_error + ' ' + rcpt_domain + ' ' + size + ' ' + queue_age"
                )
                .into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    admin.reload_settings().await;
    test.reload_core();

    let conn = test
        .server
        .core
        .smtp
        .queue
        .connection_strategy
        .get("test")
        .unwrap();

    assert_eq!(conn.ehlo_hostname.as_ref().unwrap(), "test.example.com");

    for is_ipv4 in [true, false] {
        for _ in 0..10 {
            let ip_host = conn.source_ip(is_ipv4).unwrap();
            if is_ipv4 {
                assert_eq!(
                    &ipv4_hosts[ipv4
                        .iter()
                        .position(|&ip| ip.into_inner() == ip_host.ip)
                        .unwrap()],
                    ip_host.host.as_ref().unwrap()
                );
            } else {
                assert_eq!(
                    &ipv6_hosts[ipv6
                        .iter()
                        .position(|&ip| ip.into_inner() == ip_host.ip)
                        .unwrap()],
                    ip_host.host.as_ref().unwrap()
                );
            }
        }
    }

    // Test strategy resolution
    let message = Message {
        created: now() - 123,
        blob_hash: Default::default(),
        received_from_ip: "1.2.3.4".parse().unwrap(),
        received_via_port: 7911,
        return_path: "test@example.com".into(),
        recipients: vec![Recipient {
            address: "recipient@foobar.com".into(),
            retry: Schedule::now(),
            notify: Schedule::now(),
            expires: QueueExpiry::Ttl(3600),
            queue: QueueName::new("test").unwrap(),
            status: Status::TemporaryFailure(ErrorDetails {
                entity: "test.example.com".into(),
                details: Error::TlsError("TLS handshake failed".into()),
            }),
            flags: 0,
            orcpt: None,
        }],
        flags: FROM_AUTHENTICATED,
        env_id: None,
        priority: 0,
        size: 978,
        metadata: Default::default(),
    };

    assert_eq!(
        test.server
            .eval_if::<String, _>(
                &test.server.core.smtp.queue.queue,
                &QueueEnvelope::new(&message, &message.recipients[0]),
                0,
            )
            .await
            .unwrap_or_else(|| "default".to_string()),
        "authenticated 1.2.3.4 7911 test tls foobar.com 978 123"
    );
}

#[test]
fn to_remote_hosts() {
    let mx: RecordSet<MX> = RecordSet {
        rrset: Arc::from(vec![
            MX {
                exchanges: vec!["mx1".into(), "mx2".into()].into_boxed_slice(),
                preference: 10,
            },
            MX {
                exchanges: vec!["mx3".into(), "mx4".into(), "mx5".into(), "mx6".into()]
                    .into_boxed_slice(),
                preference: 20,
            },
            MX {
                exchanges: vec!["mx7".into(), "mx8".into()].into_boxed_slice(),
                preference: 10,
            },
            MX {
                exchanges: vec!["mx9".into(), "mxA".into()].into_boxed_slice(),
                preference: 10,
            },
        ]),
        dnssec_status: DnssecStatus::Indeterminate,
    };
    let mx_config = MxConfig {
        max_mx: 7,
        max_multi_homed: 2,
        ip_lookup_strategy: IpLookupStrategy::Ipv4thenIpv6,
    };
    let hosts = mx.to_remote_hosts("domain", &mx_config).unwrap();
    assert_eq!(hosts.len(), 7);
    for host in hosts {
        if let NextHop::MX { host, .. } = host {
            assert!((*host.as_bytes().last().unwrap() - b'0') <= 8);
        }
    }
    let mx: RecordSet<MX> = RecordSet {
        rrset: Arc::from(vec![MX {
            exchanges: vec![".".into()].into_boxed_slice(),
            preference: 0,
        }]),
        dnssec_status: DnssecStatus::Indeterminate,
    };
    assert!(mx.to_remote_hosts("domain", &mx_config).is_none());
}

#[test]
fn parse_policy() {
    for (policy, expected_policy) in [
        (
            r"version: STSv1
mode: enforce
mx: mail.example.com
mx: *.example.net
mx: backupmx.example.com
max_age: 604800",
            Policy {
                id: "abc".to_string(),
                mode: Mode::Enforce,
                mx: vec![
                    MxPattern::Equals("mail.example.com".to_string()),
                    MxPattern::StartsWith("example.net".to_string()),
                    MxPattern::Equals("backupmx.example.com".to_string()),
                ]
                .into_boxed_slice(),
                max_age: 604800,
            },
        ),
        (
            r"version: STSv1
mode: testing
mx: gmail-smtp-in.l.google.com
mx: *.gmail-smtp-in.l.google.com
max_age: 86400
",
            Policy {
                id: "abc".to_string(),
                mode: Mode::Testing,
                mx: vec![
                    MxPattern::Equals("gmail-smtp-in.l.google.com".to_string()),
                    MxPattern::StartsWith("gmail-smtp-in.l.google.com".to_string()),
                ]
                .into_boxed_slice(),
                max_age: 86400,
            },
        ),
    ] {
        assert_eq!(
            Policy::parse(policy, expected_policy.id.to_string()).unwrap(),
            expected_policy
        );
    }
}

#[test]
fn aggregate_to_timestamp() {
    for (freq, date, expected) in [
        (
            AggregateFrequency::Hourly,
            "2023-01-24T09:10:40Z",
            "2023-01-24T09:00:00Z",
        ),
        (
            AggregateFrequency::Daily,
            "2023-01-24T09:10:40Z",
            "2023-01-24T00:00:00Z",
        ),
        (
            AggregateFrequency::Weekly,
            "2023-01-24T09:10:40Z",
            "2023-01-22T00:00:00Z",
        ),
        (
            AggregateFrequency::Weekly,
            "2023-01-28T23:59:59Z",
            "2023-01-22T00:00:00Z",
        ),
        (
            AggregateFrequency::Weekly,
            "2023-01-22T23:59:59Z",
            "2023-01-22T00:00:00Z",
        ),
    ] {
        assert_eq!(
            DateTime::from_timestamp(
                freq.to_timestamp_(DateTime::parse_rfc3339(date).unwrap()) as i64
            )
            .to_rfc3339(),
            expected,
            "failed for {freq:?} {date} {expected}"
        );
    }
}
