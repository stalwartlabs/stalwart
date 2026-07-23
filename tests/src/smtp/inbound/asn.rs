/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::server::TestServerBuilder;
use registry::{
    schema::structs::{Asn, AsnDns, AsnResource},
    types::map::Map,
};
use std::time::{Duration, Instant};

#[ignore]
#[tokio::test]
async fn asn() {
    let mut test = TestServerBuilder::new("smtp_asn_test")
        .await
        .with_http_listener(19011)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;

    let admin = test.account("admin");
    admin
        .registry_create_object(Asn::Dns(AsnDns {
            index_asn: 0,
            index_asn_name: 3.into(),
            index_country: 2.into(),
            separator: '|'.to_string(),
            zone_ip_v4: "origin.asn.cymru.com".to_string(),
            zone_ip_v6: "origin6.asn.cymru.com".to_string(),
        }))
        .await;
    admin.reload_settings().await;
    test.reload_core();
    let admin = test.account("admin");

    for (ip, asn, asn_name, country) in [
        ("8.8.8.8", 15169, "arin", "US"),
        ("1.1.1.1", 13335, "apnic", "AU"),
        ("2a01:4f9:c011:b43c::1", 24940, "ripencc", "DE"),
        ("1.33.1.1", 2514, "apnic", "JP"),
    ] {
        let result = test.server.lookup_asn_country(ip.parse().unwrap()).await;
        println!("{ip}: {result:?}");
        assert_eq!(result.asn.as_ref().map(|r| r.id), Some(asn));
        assert_eq!(
            result.asn.as_ref().and_then(|r| r.name.as_deref()),
            Some(asn_name)
        );
        assert_eq!(result.country.as_ref().map(|s| s.as_str()), Some(country));
    }

    admin
        .registry_create_object(Asn::Resource(AsnResource {
            asn_urls: Map::new(vec![
                "https://cdn.jsdelivr.net/npm/@ip-location-db/asn/asn-ipv4.csv".to_string(),
                "https://cdn.jsdelivr.net/npm/@ip-location-db/asn/asn-ipv6.csv".to_string(),
            ]),
            expires: 86_400_100u64.into(),
            geo_urls: Map::new(vec![
                concat!(
                    "https://cdn.jsdelivr.net/npm/@ip-location-db/geolite2-geo-whois-",
                    "asn-country/geolite2-geo-whois-asn-country-ipv4.csv"
                )
                .to_string(),
                concat!(
                    "https://cdn.jsdelivr.net/npm/@ip-location-db/geolite2-geo-whois-",
                    "asn-country/geolite2-geo-whois-asn-country-ipv6.csv"
                )
                .to_string(),
            ]),
            max_size: 100 * 1024 * 1024,
            timeout: 100_000u64.into(),
            ..Default::default()
        }))
        .await;
    admin.reload_settings().await;
    test.reload_core();

    test.server
        .lookup_asn_country("8.8.8.8".parse().unwrap())
        .await;
    let time = Instant::now();
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if test.server.inner.data.asn_geo_data.lock.available_permits() > 0 {
            break;
        }
    }
    println!("Fetch took {:?}", time.elapsed());

    for (ip, asn, asn_name, country) in [
        ("8.8.8.8", 15169, "Google LLC", "US"),
        ("1.1.1.1", 13335, "Cloudflare, Inc.", "AU"),
        ("2a01:4f9:c011:b43c::1", 24940, "Hetzner Online GmbH", "FI"),
        ("1.33.1.1", 2514, "NTT PC Communications, Inc.", "JP"),
    ] {
        let result = test.server.lookup_asn_country(ip.parse().unwrap()).await;
        println!("{ip}: {result:?}");
        assert_eq!(result.asn.as_ref().map(|r| r.id), Some(asn));
        assert_eq!(
            result.asn.as_ref().and_then(|r| r.name.as_deref()),
            Some(asn_name)
        );
        assert_eq!(result.country.as_ref().map(|s| s.as_str()), Some(country));
    }
}
