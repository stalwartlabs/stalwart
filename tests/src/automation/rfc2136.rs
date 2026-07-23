/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{net::Ipv4Addr, time::Duration as StdDuration};

use common::network::dns::update::DnsUpdater;
use dns_update::{DnsRecord, DnsRecordType, TLSARecord, TlsaCertUsage, TlsaMatching, TlsaSelector};
use registry::{
    schema::{
        enums::{IpProtocol, TsigAlgorithm},
        structs::{DnsServer, DnsServerTsig, SecretKey, SecretKeyValue},
    },
    types::duration::Duration,
};

use crate::utils::server::TestServer;

const ZONE: &str = "stalwart.test";
const KEY_B64: &str = "c3RhbHdhcnQtdGVzdC10c2lnLXNlY3JldC1rZXkxMjM0NTY3ODkw";

pub async fn test(test: &TestServer) {
    println!("Running RFC2136 (PowerDNS) tests...");
    crate::utils::containers::ensure_powerdns().await;

    let udp = DnsUpdater::build(dns_server(IpProtocol::Udp), test.server.core.clone())
        .await
        .expect("Failed to build UDP RFC2136 updater");

    // Create, replace and delete an A record over UDP (TSIG signed)
    let a_name = "rfc2136-a.stalwart.test";
    udp.updater
        .set_rrset(
            a_name,
            DnsRecordType::A,
            60,
            vec![DnsRecord::A(Ipv4Addr::new(10, 0, 0, 1))],
            ZONE,
        )
        .await
        .expect("set A");
    assert_eq!(
        list(&udp, a_name, DnsRecordType::A, 1).await,
        vec![DnsRecord::A(Ipv4Addr::new(10, 0, 0, 1))]
    );

    udp.updater
        .set_rrset(
            a_name,
            DnsRecordType::A,
            60,
            vec![DnsRecord::A(Ipv4Addr::new(10, 0, 0, 2))],
            ZONE,
        )
        .await
        .expect("replace A");
    assert_eq!(
        list(&udp, a_name, DnsRecordType::A, 1).await,
        vec![DnsRecord::A(Ipv4Addr::new(10, 0, 0, 2))]
    );

    udp.updater
        .set_rrset(a_name, DnsRecordType::A, 0, vec![], ZONE)
        .await
        .expect("delete A");
    assert!(list(&udp, a_name, DnsRecordType::A, 0).await.is_empty());

    // Publish two TLSA records at the same owner in a single set_rrset call
    let tlsa_name = "_25._tcp.rfc2136-tlsa.stalwart.test";
    let leaf: Vec<u8> = (0..32).collect();
    let intermediate: Vec<u8> = (32..64).collect();
    udp.updater
        .set_rrset(
            tlsa_name,
            DnsRecordType::TLSA,
            60,
            vec![
                DnsRecord::TLSA(TLSARecord {
                    cert_usage: TlsaCertUsage::DaneEe,
                    selector: TlsaSelector::Spki,
                    matching: TlsaMatching::Sha256,
                    cert_data: leaf.clone(),
                }),
                DnsRecord::TLSA(TLSARecord {
                    cert_usage: TlsaCertUsage::DaneTa,
                    selector: TlsaSelector::Spki,
                    matching: TlsaMatching::Sha256,
                    cert_data: intermediate.clone(),
                }),
            ],
            ZONE,
        )
        .await
        .expect("set TLSA");
    let tlsa = list(&udp, tlsa_name, DnsRecordType::TLSA, 2).await;
    let cert_datas: Vec<Vec<u8>> = tlsa
        .iter()
        .filter_map(|r| match r {
            DnsRecord::TLSA(t) => Some(t.cert_data.clone()),
            _ => None,
        })
        .collect();
    assert!(cert_datas.contains(&leaf), "leaf TLSA missing: {tlsa:?}");
    assert!(
        cert_datas.contains(&intermediate),
        "intermediate TLSA missing: {tlsa:?}"
    );
    udp.updater
        .set_rrset(tlsa_name, DnsRecordType::TLSA, 0, vec![], ZONE)
        .await
        .expect("cleanup TLSA");

    // The TCP transport must also attach the TSIG signer
    let tcp = DnsUpdater::build(dns_server(IpProtocol::Tcp), test.server.core.clone())
        .await
        .expect("Failed to build TCP RFC2136 updater");
    let txt_name = "rfc2136-txt.stalwart.test";
    tcp.updater
        .set_rrset(
            txt_name,
            DnsRecordType::TXT,
            60,
            vec![DnsRecord::TXT("rfc2136-tcp-signed".to_string())],
            ZONE,
        )
        .await
        .expect("set TXT over TCP");
    assert_eq!(
        list(&tcp, txt_name, DnsRecordType::TXT, 1).await,
        vec![DnsRecord::TXT("rfc2136-tcp-signed".to_string())]
    );
    tcp.updater
        .set_rrset(txt_name, DnsRecordType::TXT, 0, vec![], ZONE)
        .await
        .expect("cleanup TXT");
}

async fn list(
    updater: &DnsUpdater,
    name: &str,
    record_type: DnsRecordType,
    expected_len: usize,
) -> Vec<DnsRecord> {
    let mut latest = Vec::new();
    for _ in 0..20 {
        latest = updater
            .updater
            .list_rrset(name, record_type, ZONE)
            .await
            .unwrap_or_default();
        if latest.len() == expected_len {
            return latest;
        }
        tokio::time::sleep(StdDuration::from_millis(50)).await;
    }
    latest
}

fn dns_server(protocol: IpProtocol) -> DnsServer {
    DnsServer::Tsig(DnsServerTsig {
        host: "127.0.0.1".parse().unwrap(),
        port: 5300,
        key_name: "stalwart-update-key".to_string(),
        key: SecretKey::Value(SecretKeyValue {
            secret: KEY_B64.into(),
        }),
        protocol,
        tsig_algorithm: TsigAlgorithm::HmacSha256,
        description: "Test RFC2136 DNS server".to_string(),
        member_tenant_id: None,
        timeout: Duration::from_millis(10_000),
        ttl: Duration::from_millis(60_000),
        polling_interval: Duration::from_millis(100),
        propagation_timeout: Duration::from_millis(10_000),
        propagation_delay: None,
    })
}
