/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::net::IpAddr;

use crate::smtp::TestSMTP;
use ::smtp::outbound::NextHop;
use common::{
    Core,
    config::smtp::{
        queue::{MxConfig, QueueExpiry, QueueName},
        report::AggregateFrequency,
        resolver::{Mode, MxPattern, Policy},
    },
};
use mail_auth::{IpLookupStrategy, MX};
use mail_parser::DateTime;
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
use store::write::now;
use utils::config::Config;

const CONFIG: &str = r#"
[queue.connection.test.timeout]
connect = "10s"

[queue.connection.test]
ehlo-hostname = "test.example.com"
source-ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", 
              "a:b::1", "a:b::2", "a:b::3", "a:b::4"]

[queue.source-ip."10.0.0.1"]
ehlo-hostname = "test1.example.com"

[queue.source-ip."10.0.0.2"]
ehlo-hostname = "test2.example.com"

[queue.source-ip."10.0.0.3"]
ehlo-hostname = "test3.example.com"

[queue.source-ip."10.0.0.4"]
ehlo-hostname = "test4.example.com"

[queue.source-ip."a:b::1"]
ehlo-hostname = "test5.example.com"

[queue.source-ip."a:b::2"]
ehlo-hostname = "test6.example.com"

[queue.source-ip."a:b::3"]
ehlo-hostname = "test7.example.com"

[queue.source-ip."a:b::4"]
ehlo-hostname = "test8.example.com"

[queue.test-v4.type]
type = "mx"
ip-lookup-strategy = "ipv4_then_ipv6"

[queue.test-v6.type]
type = "mx"
ip-lookup-strategy = "ipv6_then_ipv4"

[queue.strategy]
schedule = "source + ' ' + received_from_ip + ' ' + received_via_port + ' ' + queue_name + ' ' + last_error + ' ' + rcpt_domain + ' ' + size + ' ' + queue_age"

"#;

#[tokio::test]
async fn strategies() {
    // Enable logging
    crate::enable_logging();

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

    let mut config = Config::new(CONFIG).unwrap();
    let test =
        TestSMTP::from_core(Core::parse(&mut config, Default::default(), Default::default()).await);

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
                    &ipv4_hosts[ipv4.iter().position(|&ip| ip == ip_host.ip).unwrap()],
                    ip_host.host.as_ref().unwrap()
                );
            } else {
                assert_eq!(
                    &ipv6_hosts[ipv6.iter().position(|&ip| ip == ip_host.ip).unwrap()],
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
        quota_keys: Default::default(),
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
    let mx = vec![
        MX {
            exchanges: vec!["mx1".to_string(), "mx2".to_string()],
            preference: 10,
        },
        MX {
            exchanges: vec![
                "mx3".to_string(),
                "mx4".to_string(),
                "mx5".to_string(),
                "mx6".to_string(),
            ],
            preference: 20,
        },
        MX {
            exchanges: vec!["mx7".to_string(), "mx8".to_string()],
            preference: 10,
        },
        MX {
            exchanges: vec!["mx9".to_string(), "mxA".to_string()],
            preference: 10,
        },
    ];
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
    let mx = vec![MX {
        exchanges: vec![".".to_string()],
        preference: 0,
    }];
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
                ],
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
                ],
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
