/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::server::TestServer;
use common::network::dns::update::DNS_RECORDS;
use dns_update::{CAARecord, bind::BindSerializer};
use registry::{
    schema::{
        enums::{AcmeChallengeType, DnsRecordType},
        prelude::{ObjectType, Property},
        structs::{
            AcmeProvider, CertificateManagement, CertificateManagementProperties, DkimManagement,
            DkimManagementProperties, DnsManagement, DnsManagementProperties, DnsServer,
            DnsServerCloudflare, SecretKey, SecretKeyValue,
        },
    },
    types::map::Map,
};
use serde_json::json;

const EXPECTED_ZONE: &str = r#"example.org. IN CAA 0 iodef "mailto:postmaster@example.org"
example.org. IN CAA 0 issue "pebble.letsencrypt.org"
autoconfig.example.org. IN CNAME mail.example.org.
autodiscover.example.org. IN CNAME mail.example.org.
mta-sts.example.org. IN CNAME mail.example.org.
ua-auto-config.example.org. IN CNAME mail.example.org.
example.org. IN MX 10 mx1.example.org.
example.org. IN MX 20 mx2.example.org.
_caldavs._tcp.example.org. IN SRV 0 1 443 mail.example.org.
_carddavs._tcp.example.org. IN SRV 0 1 443 mail.example.org.
_imaps._tcp.example.org. IN SRV 0 1 993 imap.example.org.
_jmap._tcp.example.org. IN SRV 0 1 443 mail.example.org.
_pop3s._tcp.example.org. IN SRV 0 1 995 pop3.example.org.
_submissions._tcp.example.org. IN SRV 0 1 465 smtp.example.org.
_25._tcp.mx1.example.org. IN TLSA 3 1 1 
_25._tcp.mx1.example.org. IN TLSA 2 1 1 
_25._tcp.mx2.example.org. IN TLSA 3 1 1 
_25._tcp.mx2.example.org. IN TLSA 2 1 1 
_443._tcp.autoconfig.example.org. IN TLSA 3 1 1 
_443._tcp.autoconfig.example.org. IN TLSA 2 1 1 
_443._tcp.autodiscover.example.org. IN TLSA 3 1 1 
_443._tcp.autodiscover.example.org. IN TLSA 2 1 1 
_443._tcp.mail.example.org. IN TLSA 3 1 1 
_443._tcp.mail.example.org. IN TLSA 2 1 1 
_443._tcp.mta-sts.example.org. IN TLSA 3 1 1 
_443._tcp.mta-sts.example.org. IN TLSA 2 1 1 
_443._tcp.ua-auto-config.example.org. IN TLSA 3 1 1 
_443._tcp.ua-auto-config.example.org. IN TLSA 2 1 1 
_465._tcp.smtp.example.org. IN TLSA 3 1 1 
_465._tcp.smtp.example.org. IN TLSA 2 1 1 
_993._tcp.imap.example.org. IN TLSA 3 1 1 
_993._tcp.imap.example.org. IN TLSA 2 1 1 
_995._tcp.pop3.example.org. IN TLSA 3 1 1 
_995._tcp.pop3.example.org. IN TLSA 2 1 1 
_dmarc.example.org. IN TXT "v=DMARC1; p=reject; rua=mailto:postmaster@example.org"
_mta-sts.example.org. IN TXT "v=STSv1; id=12942536112359691423"
_smtp._tls.example.org. IN TXT "v=TLSRPTv1; rua=mailto:postmaster@example.org"
_ua-auto-config.example.org. IN TXT "v=UAAC1; a=sha256; d=9X2mMgWAc10oSPuRKZSFBwPXEQpnxkS7SXPO8PC7euM="
_validation-persist.example.org. IN TXT "pebble.letsencrypt.org; accounturi=REDACTED"
dummy-v1-ed25519._domainkey.example.org. IN TXT "v=DKIM1; k=ed25519; h=sha256; p=REDACTED"
dummy-v1-rsa._domainkey.example.org. IN TXT "v=DKIM1; k=rsa; h=sha256; p=REDACTED"
example.org. IN TXT "v=spf1 mx -all"
mx1.example.org. IN TXT "v=spf1 a -all"
mx2.example.org. IN TXT "v=spf1 a -all"
"#;

pub async fn test(test: &TestServer) {
    println!("Running DNS Management tests...");
    let account = test.account("admin@example.org");
    DNS_RECORDS.lock().unwrap().clear();
    let domain_id = account.find_or_create_domain("example.org").await;
    account
        .registry_update_object(
            ObjectType::Domain,
            domain_id,
            json!({
                Property::CertificateManagement: CertificateManagement::Manual,
                Property::DnsManagement: DnsManagement::Manual,
                Property::DkimManagement: DkimManagement::Manual,
            }),
        )
        .await;

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
    let acme_provider_id = account
        .registry_create_object(AcmeProvider {
            directory: "https://localhost:14000/dir".to_string(),
            contact: Map::new(vec!["mailto:hello@example.org".to_string()]),
            challenge_type: AcmeChallengeType::TlsAlpn01,
            ..Default::default()
        })
        .await;

    let cert = CertificateManagement::Automatic(CertificateManagementProperties {
        acme_provider_id,
        subject_alternative_names: Default::default(),
    });
    let dns = DnsManagement::Automatic(DnsManagementProperties {
        dns_server_id,
        publish_records: Map::new(vec![
            DnsRecordType::Dkim,
            DnsRecordType::Tlsa,
            DnsRecordType::Spf,
            DnsRecordType::Mx,
            DnsRecordType::Dmarc,
            DnsRecordType::Srv,
            DnsRecordType::MtaSts,
            DnsRecordType::TlsRpt,
            DnsRecordType::Caa,
            DnsRecordType::AutoConfig,
            DnsRecordType::AutoConfigLegacy,
            DnsRecordType::AutoDiscover,
        ]),
        ..Default::default()
    });
    let dkim = DkimManagement::Automatic(DkimManagementProperties {
        selector_template: "dummy-v{version}-{algorithm}-{epoch}".to_string(),
        ..Default::default()
    });
    account
        .registry_update_object(
            ObjectType::Domain,
            domain_id,
            json!({
                Property::CertificateManagement: cert,
                Property::DnsManagement: dns,
                Property::DkimManagement: dkim,
            }),
        )
        .await;
    test.wait_for_tasks_skip_not_due().await;

    let mut records = DNS_RECORDS
        .lock()
        .unwrap()
        .iter()
        .map(|r| {
            let mut r = r.clone();

            if r.name.starts_with("dummy-") {
                let (selector, domain) = r.name.split_once("._domainkey.").unwrap();
                let selector = selector.rsplit_once('-').unwrap().0;
                r.name = format!("{selector}._domainkey.{domain}");
            }

            match &mut r.record {
                dns_update::DnsRecord::TXT(r) => {
                    if r.starts_with("v=DKIM1;") {
                        *r = r.split_once("; p=").unwrap().0.to_string() + "; p=REDACTED";
                    } else if r.contains("letsencrypt.org") {
                        *r = r.split_once("; accounturi=").unwrap().0.to_string()
                            + "; accounturi=REDACTED";
                    }
                }
                dns_update::DnsRecord::TLSA(r) => {
                    r.cert_data.clear();
                }
                dns_update::DnsRecord::CAA(CAARecord::Issue { options, .. }) => {
                    options.clear();
                }
                _ => (),
            }
            r
        })
        .collect::<Vec<_>>();

    records.sort_unstable_by_key(|r| format!("{:?}-{}-{:?}", r.record.as_type(), r.name, r.record));

    assert_eq!(BindSerializer::serialize(&records), EXPECTED_ZONE);

    // Cleanup
    account
        .registry_update_object(
            ObjectType::Domain,
            domain_id,
            json!({
                Property::CertificateManagement: CertificateManagement::Manual,
                Property::DnsManagement: DnsManagement::Manual,
                Property::DkimManagement: DkimManagement::Manual,
            }),
        )
        .await;
    account.registry_destroy_all(ObjectType::DnsServer).await;
    account.registry_destroy_all(ObjectType::AcmeProvider).await;
    account.registry_destroy_all(ObjectType::Certificate).await;
    account.registry_destroy_all(ObjectType::Task).await;
}
