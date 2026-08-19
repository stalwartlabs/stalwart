/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::net::IpAddr;

use crate::{Email, Hostname};

impl Hostname {
    pub fn new(host: &str) -> Self {
        let mut fqdn = host.trim_end_matches('.').to_lowercase();

        // Decode punycode
        if fqdn.contains("xn--") {
            let mut decoded = String::with_capacity(fqdn.len());

            for part in fqdn.split('.') {
                if !decoded.is_empty() {
                    decoded.push('.');
                }

                if let Some(puny) = part
                    .strip_prefix("xn--")
                    .and_then(idna::punycode::decode_to_string)
                    .filter(|puny| {
                        idna::domain_to_ascii(puny).is_ok_and(|reencoded| reencoded == part)
                    })
                {
                    decoded.push_str(&puny);
                } else {
                    decoded.push_str(part);
                }
            }

            fqdn = decoded;
        }

        let ip = fqdn
            .strip_prefix('[')
            .and_then(|ip| ip.strip_suffix(']'))
            .unwrap_or(&fqdn)
            .parse::<IpAddr>()
            .ok();

        Hostname {
            sld: if ip.is_none() {
                psl::domain(fqdn.as_bytes()).and_then(|domain| {
                    if domain.suffix().typ().is_some() {
                        std::str::from_utf8(domain.as_bytes()).ok().map(Into::into)
                    } else {
                        None
                    }
                })
            } else {
                None
            },
            ip,
            fqdn,
        }
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

impl Hostname {
    pub fn sld_or_default(&self) -> &str {
        self.sld.as_deref().unwrap_or(self.fqdn.as_str())
    }
}

#[cfg(test)]
mod test {
    use crate::{Email, Hostname};

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
