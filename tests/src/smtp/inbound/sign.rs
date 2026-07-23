/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    smtp::{
        inbound::TestMessage,
        session::{TestSession, VerifyResponse},
    },
    utils::{account::Account, dns::DnsCache, server::TestServerBuilder},
};
use mail_auth::{
    common::{parse::TxtRecordParser, verify::DomainKey},
    spf::Spf,
};
use registry::schema::{
    enums::{DkimCanonicalization, DkimRotationStage},
    structs::{
        CertificateManagement, Dkim1Signature, DkimManagement, DkimSignature, DnsManagement,
        Domain, Expression, SecretText, SecretTextValue, SenderAuth,
    },
};
use std::time::{Duration, Instant};
use types::id::Id;

#[tokio::test]
async fn sign_and_seal() {
    let mut test = TestServerBuilder::new("smtp_sign_test")
        .await
        .with_http_listener(19010)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;

    // Add test settings
    let admin = test.account("admin");
    let domain_id = admin
        .registry_create_object(Domain {
            name: "example.com".into(),
            certificate_management: CertificateManagement::Manual,
            dns_management: DnsManagement::Manual,
            dkim_management: DkimManagement::Manual,
            allow_relaying: true,
            ..Default::default()
        })
        .await;
    admin.create_dkim_signatures(domain_id).await;
    admin.mta_no_auth().await;
    admin.mta_add_all_headers().await;
    admin
        .registry_create_object(SenderAuth {
            dmarc_verify: Expression {
                else_: "relaxed".into(),
                ..Default::default()
            },
            reverse_ip_verify: Expression {
                else_: "relaxed".into(),
                ..Default::default()
            },
            spf_ehlo_verify: Expression {
                else_: "relaxed".into(),
                ..Default::default()
            },
            spf_from_verify: Expression {
                else_: "relaxed".into(),
                ..Default::default()
            },
            arc_verify: Expression {
                else_: "strict".into(),
                ..Default::default()
            },
            dkim_sign_domain: Expression {
                else_: "'example.com'".into(),
                ..Default::default()
            },
            dkim_verify: Expression {
                else_: "relaxed".into(),
                ..Default::default()
            },
            dkim_strict: false,
        })
        .await;
    admin.reload_settings().await;
    test.reload_core();
    test.expect_reload_settings().await;

    // Add SPF, DKIM and DMARC records
    test.server.txt_add(
        "mx.example.com",
        Spf::parse(b"v=spf1 ip4:10.0.0.1 ip4:10.0.0.2 -all").unwrap(),
        Instant::now() + Duration::from_secs(5),
    );
    test.server.txt_add(
        "example.com",
        Spf::parse(b"v=spf1 ip4:10.0.0.1 -all").unwrap(),
        Instant::now() + Duration::from_secs(5),
    );
    test.server.txt_add(
        "ed._domainkey.scamorza.org",
        DomainKey::parse(
            concat!(
                "v=DKIM1; k=ed25519; ",
                "p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
            )
            .as_bytes(),
        )
        .unwrap(),
        Instant::now() + Duration::from_secs(5),
    );
    test.server.txt_add(
        "rsa._domainkey.manchego.org",
        DomainKey::parse(
            concat!(
                "v=DKIM1; t=s; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ",
                "KBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYt",
                "IxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v",
                "/RtdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhi",
                "tdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB",
            )
            .as_bytes(),
        )
        .unwrap(),
        Instant::now() + Duration::from_secs(5),
    );

    // Test DKIM signing
    let mut session = test.new_mta_session();
    session.data.remote_ip_str = "10.0.0.2".into();
    session.eval_session_params().await;
    session.ehlo("mx.example.com").await;
    session
        .send_message(
            "bill@foobar.org",
            &["jdoe@example.com"],
            "test:no_dkim",
            "250",
        )
        .await;
    test.expect_message()
        .await
        .read_lines(&test)
        .await
        .assert_contains(
            "DKIM-Signature: v=1; a=rsa-sha256; s=rsa; d=example.com; c=simple/relaxed;",
        );

    // Test ARC verify
    session
        .send_message("bill@foobar.org", &["jdoe@example.com"], "test:arc", "250")
        .await;
    test.expect_message().await;

    /*
    // DMARC WG is ending the ARC experiment

    .read_lines(&test)
        .await
        .assert_contains("ARC-Seal: i=3; a=ed25519-sha256; s=ed; d=example.com; cv=pass;")
        .assert_contains(
            "ARC-Message-Signature: i=3; a=ed25519-sha256; s=ed; d=example.com; c=relaxed/simple;",
        );

    // Test ARC sealing of a DKIM signed message
    session
        .send_message("bill@foobar.org", &["jdoe@example.com"], "test:dkim", "250")
        .await;
    test.expect_message()
        .await
        .read_lines(&test)
        .await
        .assert_contains("ARC-Seal: i=1; a=ed25519-sha256; s=ed; d=example.com; cv=none;")
        .assert_contains(
            "ARC-Message-Signature: i=1; a=ed25519-sha256; s=ed; d=example.com; c=relaxed/simple;",
        );*/
}

impl Account {
    pub async fn create_dkim_signatures(&self, domain_id: Id) -> Vec<Id> {
        let rsa_id = self
            .registry_create_object(DkimSignature::Dkim1RsaSha256(Dkim1Signature {
                stage: DkimRotationStage::Active,
                selector: "rsa".to_string(),
                canonicalization: DkimCanonicalization::SimpleRelaxed,
                domain_id,
                private_key: SecretText::Text(SecretTextValue {
                    secret: RSA_KEY.to_string(),
                }),
                ..Default::default()
            }))
            .await;

        let ed_id = self
            .registry_create_object(DkimSignature::Dkim1Ed25519Sha256(Dkim1Signature {
                stage: DkimRotationStage::Active,
                selector: "ed".to_string(),
                canonicalization: DkimCanonicalization::RelaxedSimple,
                domain_id,
                private_key: SecretText::Text(SecretTextValue {
                    secret: ED25519_KEY.to_string(),
                }),
                ..Default::default()
            }))
            .await;

        vec![rsa_id, ed_id]
    }
}

const RSA_KEY: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAv9XYXG3uK95115mB4nJ37nGeNe2CrARm1agrbcnSk5oIaEfM
ZLUR/X8gPzoiNHZcfMZEVR6bAytxUhc5EvZIZrjSuEEeny+fFd/cTvcm3cOUUbIa
UmSACj0dL2/KwW0LyUaza9z9zor7I5XdIl1M53qVd5GI62XBB76FH+Q0bWPZNkT4
NclzTLspD/MTpNCCPhySM4Kdg5CuDczTH4aNzyS0TqgXdtw6A4Sdsp97VXT9fkPW
9rso3lrkpsl/9EQ1mR/DWK6PBmRfIuSFuqnLKY6v/z2hXHxF7IoojfZLa2kZr9Ae
d4l9WheQOTA19k5r2BmlRw/W9CrgCBo0Sdj+KQIDAQABAoIBAFPChEi/OvnulReB
ECQWhOUYuNKlFKQU++2YEvZJ4+bMn5UgnE7wfJ1pj2Pr9xlfALz+OMHNrjMxGbaV
KzdrT2uCkYcf78XjnhuH9gKIiXDUv4L4N+P3u6w8yOx4bFgOS9IjS53yDOPM7SC5
g6dIg5aigHaHlffqIuFFv4yQMI/+Ai+zBKxS7wRhxK/7nnAuo28fe5MEdp57ho9/
AGlDNsdg9zCgjwhokwFE3+AaD+bkUFm4gQ1XjkUFrlmnQn8vDQ0i9toEWhCj+UPY
iOKL63MJnr90MXTXWLHoFj99wBp//mYygbF9Lj8fa28/oa8LWp3Jhb7QeMgH46iv
3aLHbTECgYEA5M2dAw+nyMw9vYlkMejhwObKYP8Mr/6zcGMLCalYvRJM5iUAM0JI
H6sM6pV9/nv167cbKocj3xYPdtE7FPOn4132MLM8Ne1f8nPE64Qrcbj5WBXvLnU8
hpWbwe2Z8h7UUMKx6q4F1/TXYkc3ScxYwfjM4mP/pLsAOgVzRSEEgrUCgYEA1qNQ
xaQHNWZ1O8WuTnqWd5JSsic6iURAmUcLeFDZY2PWhVoaQ8L/xMQhDYs1FIbLWArW
4Qq3Ibu8AbSejAKuaJz7Uf26PX+PYVUwAOO0qamCJ8d/qd6So7qWMDyAY2yXI39Y
1nMqRjr7bkEsggAZao7BKqA7ZtmogjOusBT38iUCgYEA06agJ8TDoKvOMRZ26PRU
YO0dKLzGL8eclcoI29cbj0rud7aiiMg3j5PbTuUat95TjsjDCIQaWrM9etvxm2AJ
Xfn9Uu96MyhyKQWOk46f4YMKpMElkARDCPw8KRhx39dE77AqhLyWCz8iPndCXbH6
KPTOEl4OjYOuof2Is9nnIkECgYBh948RdsnXhNlzm8nwhiGRmBbou+EK8D0v+O5y
Tyy6IcKzgSnFzgZh8EdJ4EUtBk1f9SqY8wQdgIvSl3daXorusuA/TzkngsaV3YUY
ktZOLlF7CKLrjOyPkMWmZKcROmpNyH1q/IvKHHfQnizLdXIkYd4nL5WNX0F7lE1i
j1+QhQKBgB2lviBK7rJFwlFYdQUP1NAN2dKxMZk8uJS8JglHrM0+8nRI83HbTdEQ
vB0ManEKBkbS4T5n+gRtdEqKSDmWDTXDlrBfcdCHNQLwYtBpOotCqQn/AmfjcPBl
byAbwh4+HiZ5JISoRZpiZqy67aJNVoXmdtb/E9mi7ozzytpxMNql
-----END RSA PRIVATE KEY-----
"#;

const ED25519_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIAO3hAf144lTAVjTkht3ZwBTK0CMCCd1bI0alggneN3B
-----END PRIVATE KEY-----
"#;
