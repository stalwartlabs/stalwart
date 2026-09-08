/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{Email, Hostname};
use std::net::IpAddr;

const MAX_IP_ADDR_LEN: usize = 45;

#[inline]
pub(crate) fn can_be_ip_addr(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() > MAX_IP_ADDR_LEN {
        return false;
    }
    match bytes.first() {
        Some(b':') => true,
        Some(byte) if byte.is_ascii_digit() => true,
        Some(byte) if byte.is_ascii_hexdigit() => bytes.contains(&b':'),
        _ => false,
    }
}

#[inline]
fn ip_candidate(fqdn: &str) -> Option<&str> {
    let text = fqdn
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(fqdn);

    can_be_ip_addr(text).then_some(text)
}

fn decode_punycode(fqdn: &str) -> String {
    let mut decoded = String::with_capacity(fqdn.len());

    for part in fqdn.split('.') {
        if !decoded.is_empty() {
            decoded.push('.');
        }

        if let Some(puny) = part
            .strip_prefix("xn--")
            .and_then(idna::punycode::decode_to_string)
            .filter(|puny| idna::domain_to_ascii(puny).is_ok_and(|reencoded| reencoded == part))
        {
            decoded.push_str(&puny);
        } else {
            decoded.push_str(part);
        }
    }

    decoded
}

fn second_level_domain(fqdn: &str) -> Option<String> {
    psl::domain(fqdn.as_bytes()).and_then(|domain| {
        if domain.suffix().typ().is_some() {
            std::str::from_utf8(domain.as_bytes()).ok().map(Into::into)
        } else {
            None
        }
    })
}

impl Hostname {
    pub fn new(host: &str) -> Self {
        let mut fqdn = host.trim_end_matches('.').to_lowercase();

        if fqdn.contains("xn--") {
            fqdn = decode_punycode(&fqdn);
        }

        let ip = ip_candidate(&fqdn).and_then(|text| text.parse::<IpAddr>().ok());

        Hostname {
            sld: if ip.is_none() {
                second_level_domain(&fqdn)
            } else {
                None
            },
            ip,
            fqdn,
        }
    }

    pub fn sld_or_default(&self) -> &str {
        self.sld.as_deref().unwrap_or(self.fqdn.as_str())
    }
}

impl Email {
    pub fn new(address: &str) -> Self {
        let address = address.to_lowercase();
        let (local_part, domain) = address.rsplit_once('@').unwrap_or((address.as_str(), ""));

        Email {
            local_part: local_part.into(),
            domain_part: Hostname::new(domain),
            address,
        }
    }
}

#[cfg(test)]
mod test {
    use super::can_be_ip_addr;
    use crate::{Email, Hostname};
    use std::net::IpAddr;

    #[test]
    fn ip_pre_check_never_rejects_a_parseable_address() {
        let mut inputs = vec![
            "127.0.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "256.1.1.1",
            "1.2.3",
            "1.2.3.4.5",
            "::",
            "::1",
            "1::",
            "fe80::1",
            "2001:db8::1",
            "FE80::1",
            "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255",
            "::ffff:1.2.3.4",
            "a::1",
            "abcd::",
            "g::1",
            "mail.example.com",
            "example.com",
            "localhost",
            "ffff.example",
            "1example.com",
            "-1.2.3.4",
            " 1.2.3.4",
            "1.2.3.4 ",
            "",
            "[::1]",
            ":",
            ".",
            "0x7f.0.0.1",
            "1.2.3.04",
            "1.2.3.4:25",
            "fe80::1%lo0",
        ];
        let long = "1".repeat(46);
        inputs.push(long.as_str());
        for text in inputs {
            if text.parse::<IpAddr>().is_ok() {
                assert!(
                    can_be_ip_addr(text),
                    "{text:?} parses but was rejected by the pre-check"
                );
            }
        }
        assert!(!can_be_ip_addr("mail.example.com"));
        assert!(!can_be_ip_addr(""));
        assert!(!can_be_ip_addr(&"1".repeat(46)));
        assert!(can_be_ip_addr(&"1".repeat(45)));
    }

    #[test]
    fn hostname_ip_literals_and_edge_cases() {
        for (host, fqdn, ip, sld) in [
            ("[::1]", "[::1]", Some("::1"), None),
            ("[1.2.3.4]", "[1.2.3.4]", Some("1.2.3.4"), None),
            ("1.2.3.4", "1.2.3.4", Some("1.2.3.4"), None),
            ("FE80::1", "fe80::1", Some("fe80::1"), None),
            ("256.1.1.1", "256.1.1.1", None, None),
            ("1.2.3.4.", "1.2.3.4", Some("1.2.3.4"), None),
            ("Example.COM...", "example.com", None, Some("example.com")),
            ("", "", None, None),
            ("..", "", None, None),
            ("a..b.com", "a..b.com", None, Some("b.com")),
            ("localhost", "localhost", None, None),
            (
                "ffff.example.com",
                "ffff.example.com",
                None,
                Some("example.com"),
            ),
        ] {
            let parsed = Hostname::new(host);
            assert_eq!(parsed.fqdn, fqdn, "fqdn of {host:?}");
            assert_eq!(
                parsed.ip.map(|ip| ip.to_string()).as_deref(),
                ip,
                "ip of {host:?}"
            );
            assert_eq!(parsed.sld.as_deref(), sld, "sld of {host:?}");
        }
    }

    #[test]
    fn email_parts() {
        let email = Email::new("John.Doe@Example.COM");
        assert_eq!(email.address, "john.doe@example.com");
        assert_eq!(email.local_part, "john.doe");
        assert_eq!(email.domain_part.fqdn, "example.com");
        assert_eq!(
            email.classifier_parts(),
            Some(("john.doe@", "@example.com"))
        );
        let nested = Email::new("a@b@c.com");
        assert_eq!(nested.local_part, "a@b");
        assert_eq!(nested.domain_part.fqdn, "c.com");
        assert_eq!(nested.classifier_parts(), Some(("a@", "@b@c.com")));
        let bare = Email::new("postmaster");
        assert_eq!(bare.local_part, "postmaster");
        assert_eq!(bare.domain_part.fqdn, "");
        assert!(!bare.is_valid());
        assert!(Email::new("").local_part.is_empty());
    }

    #[test]
    fn hostname_punycode_round_trip() {
        for (host, fqdn, sld) in [
            ("mail.example.com", "mail.example.com", Some("example.com")),
            (
                "MAIL.Example.CO.UK.",
                "mail.example.co.uk",
                Some("example.co.uk"),
            ),
            (
                "mail.xn--eebajf.xn--9dbq2a",
                "mail.\u{5de}\u{5d9}\u{5d9}\u{5dc}.\u{5e7}\u{5d5}\u{5dd}",
                Some("\u{5de}\u{5d9}\u{5d9}\u{5dc}.\u{5e7}\u{5d5}\u{5dd}"),
            ),
            ("xn--gmail-.com", "xn--gmail-.com", Some("xn--gmail-.com")),
            (
                "xn--example-.org",
                "xn--example-.org",
                Some("xn--example-.org"),
            ),
            ("xn--.com", "xn--.com", Some("xn--.com")),
            ("127.0.0.1", "127.0.0.1", None),
        ] {
            let parsed = Hostname::new(host);
            assert_eq!(parsed.fqdn, fqdn, "fqdn of {host:?}");
            assert_eq!(parsed.sld.as_deref(), sld, "sld of {host:?}");
        }
    }

    #[test]
    fn email_a_label_and_u_label_are_equal() {
        assert_eq!(
            Email::new("bill@xn--eebajf.xn--9dbq2a"),
            Email::new("bill@\u{5de}\u{5d9}\u{5d9}\u{5dc}.\u{5e7}\u{5d5}\u{5dd}")
        );
        assert_ne!(
            Email::new("bill@example.com"),
            Email::new("bob@example.com")
        );
        assert_ne!(Email::new("postmaster"), Email::new("mailer-daemon"));
        assert_ne!(
            Email::new("victim@xn--gmail-.com"),
            Email::new("victim@gmail.com")
        );
    }
}
