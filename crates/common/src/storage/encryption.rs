/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::auth::EncryptionKeys;
use encodify::base64::LENIENT;
use registry::schema::structs::PublicKey;
use sequoia_openpgp::{Cert, parse::Parse, policy::StandardPolicy, types::KeyFlags};
use std::{borrow::Cow, str::SplitInclusive};

const P: StandardPolicy<'static> = StandardPolicy::new();

const ARMOR_BEGIN: &str = "-----BEGIN ";
const ARMOR_END: &str = "-----END";
const ARMOR_DASHES: &str = "-----";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionMethod {
    PGP,
    SMIME,
}

pub struct EncryptionParams {
    pub certs: EncryptionKeys,
    pub method: EncryptionMethod,
}

pub fn parse_public_key(pk: &PublicKey) -> Result<Option<EncryptionParams>, Cow<'static, str>> {
    let mut method = None;
    let mut certs: Vec<Box<[u8]>> = Vec::new();
    let mut has_usable_pgp_key = false;

    for block in ArmoredBlocks::new(&pk.key) {
        let block = block?;
        if contains_ignore_ascii_case(block.label, "PRIVATE") {
            return Err("Private keys cannot be used as public keys".into());
        }
        let block_method = if contains_ignore_ascii_case(block.label, "CERTIFICATE") {
            EncryptionMethod::SMIME
        } else if contains_ignore_ascii_case(block.label, "PGP") {
            EncryptionMethod::PGP
        } else {
            continue;
        };

        match method {
            Some(method) if method != block_method => {
                return Err("Cannot mix OpenPGP and S/MIME certificates".into());
            }
            _ => method = Some(block_method),
        }

        match block_method {
            EncryptionMethod::PGP => {
                let cert = Cert::from_bytes(block.armored.as_bytes())
                    .map_err(|err| format!("Failed to decode OpenPGP public key: {err}"))?;
                if cert.is_tsk() {
                    return Err("Private keys cannot be used as public keys".into());
                }
                has_usable_pgp_key |= has_pgp_keys(&cert);
                certs.push(block.armored.as_bytes().into());
            }
            EncryptionMethod::SMIME => {
                let cert = LENIENT
                    .decode(block.body)
                    .map_err(|_| Cow::from("Failed to decode base64 certificate."))?;
                let is_complete = rasn::der::decode_with_remainder::<rasn_pkix::Certificate>(&cert)
                    .map_err(|err| format!("Failed to decode X509 certificate: {err}"))?
                    .1
                    .is_empty();
                if !is_complete {
                    return Err("Unexpected data after X509 certificate".into());
                }
                certs.push(cert.into_boxed_slice());
            }
        }
    }

    match method {
        Some(EncryptionMethod::PGP) if !has_usable_pgp_key => {
            Err("Could not find any suitable keys in OpenPGP public key".into())
        }
        Some(method) => Ok(Some(EncryptionParams {
            method,
            certs: certs.into_boxed_slice(),
        })),
        None if pk.key.trim().is_empty() => Ok(None),
        None => Err("No OpenPGP public key or X.509 certificate found".into()),
    }
}

struct ArmoredBlock<'x> {
    label: &'x str,
    armored: &'x str,
    body: &'x str,
}

struct ArmoredBlocks<'x> {
    text: &'x str,
    lines: SplitInclusive<'x, char>,
    offset: usize,
}

impl<'x> ArmoredBlocks<'x> {
    fn new(text: &'x str) -> Self {
        ArmoredBlocks {
            text,
            lines: text.split_inclusive('\n'),
            offset: 0,
        }
    }

    fn next_line(&mut self) -> Option<(usize, &'x str)> {
        let line = self.lines.next()?;
        let start = self.offset;
        self.offset += line.len();
        Some((start, line))
    }

    fn fail(
        &mut self,
        reason: &'static str,
    ) -> Option<Result<ArmoredBlock<'x>, Cow<'static, str>>> {
        self.lines = "".split_inclusive('\n');
        Some(Err(reason.into()))
    }
}

impl<'x> Iterator for ArmoredBlocks<'x> {
    type Item = Result<ArmoredBlock<'x>, Cow<'static, str>>;

    fn next(&mut self) -> Option<Self::Item> {
        let (block_start, label) = loop {
            let (line_start, line) = self.next_line()?;
            let begin = line.trim();
            if begin.is_empty() {
                continue;
            }
            let Some(label) = begin
                .strip_prefix(ARMOR_BEGIN)
                .and_then(|label| label.strip_suffix(ARMOR_DASHES))
                .filter(|label| !label.is_empty())
            else {
                return self.fail("Unexpected text outside of a PEM or OpenPGP armor block");
            };
            break (line_start + line.len() - line.trim_start().len(), label);
        };
        let body_start = self.offset;

        loop {
            let Some((line_start, line)) = self.next_line() else {
                return self.fail("PEM or OpenPGP armor block is missing its END line");
            };
            let line = line.trim();
            if let Some(end_label) = line.strip_prefix(ARMOR_END) {
                if end_label
                    .strip_prefix(' ')
                    .and_then(|end_label| end_label.strip_suffix(ARMOR_DASHES))
                    != Some(label)
                {
                    return self
                        .fail("PEM or OpenPGP armor END line does not match its BEGIN line");
                }
                return match (
                    self.text.get(block_start..self.offset),
                    self.text.get(body_start..line_start),
                ) {
                    (Some(armored), Some(body)) => Some(Ok(ArmoredBlock {
                        label,
                        armored,
                        body,
                    })),
                    _ => self.fail("Invalid PEM or OpenPGP armor block"),
                };
            } else if line.starts_with(ARMOR_BEGIN) {
                return self.fail("PEM or OpenPGP armor block is missing its END line");
            }
        }
    }
}

fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

fn has_pgp_keys(cert: &Cert) -> bool {
    cert.keys()
        .with_policy(&P, None)
        .supported()
        .alive()
        .revoked(false)
        .key_flags(KeyFlags::empty().set_transport_encryption())
        .next()
        .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use encodify::base64::STANDARD;
    use sequoia_openpgp::{cert::CertBuilder, serialize::SerializeInto};
    use std::time::{Duration, SystemTime};

    const CERT_PGP: &str = include_str!("../../../../tests/resources/crypto/cert_pgp.pem");
    const CERT_MIXED: &str = include_str!("../../../../tests/resources/crypto/cert_mixed.pem");
    const CERT_SMIME: &str = include_str!("../../../../tests/resources/crypto/cert_smime.pem");
    const PGP_BEGIN: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n";
    const PGP_END: &str = "-----END PGP PUBLIC KEY BLOCK-----\n";

    fn parse(key: impl Into<String>) -> Result<Option<EncryptionParams>, Cow<'static, str>> {
        parse_public_key(&PublicKey {
            key: key.into(),
            ..Default::default()
        })
    }

    fn parse_ok(key: impl Into<String>) -> EncryptionParams {
        parse(key)
            .expect("key must parse")
            .expect("key must not be treated as absent")
    }

    fn pgp_block(key: &str) -> String {
        let (block, _) = key.split_once(PGP_END).expect("PGP block");
        format!("{block}{PGP_END}")
    }

    fn second_pgp_key() -> String {
        pgp_block(CERT_MIXED)
    }

    fn with_headers(key: &str, headers: &str) -> String {
        key.replacen(
            &format!("{PGP_BEGIN}\n"),
            &format!("{PGP_BEGIN}{headers}\n"),
            1,
        )
    }

    fn generated_key(expired: bool) -> Cert {
        let builder = CertBuilder::new()
            .add_userid("generated@example.org")
            .add_transport_encryption_subkey();
        if expired {
            builder
                .set_creation_time(SystemTime::now() - Duration::from_secs(2 * 86400))
                .set_validity_period(Duration::from_secs(86400))
        } else {
            builder
        }
        .generate()
        .expect("key generation")
        .0
    }

    fn armored(bytes: Vec<u8>) -> String {
        String::from_utf8(bytes).expect("armored text")
    }

    #[test]
    fn expired_key_next_to_a_live_key_is_kept() {
        let expired = armored(generated_key(true).armored().to_vec().expect("armor"));
        let params = parse_ok(format!("{CERT_PGP}{expired}"));
        assert_eq!(params.method, EncryptionMethod::PGP);
        assert_eq!(params.certs.len(), 2);
        assert_eq!(&*params.certs[1], expired.as_bytes());

        assert!(parse(expired).is_err());
    }

    #[test]
    fn private_keys_are_rejected() {
        let cert = generated_key(false);
        let public = armored(cert.armored().to_vec().expect("armor"));
        assert_eq!(parse_ok(public).method, EncryptionMethod::PGP);

        let tsk = armored(cert.as_tsk().armored().to_vec().expect("armor"));
        assert!(tsk.contains("PGP PRIVATE KEY BLOCK"));
        let relabeled = tsk.replace("PGP PRIVATE KEY BLOCK", "PGP PUBLIC KEY BLOCK");
        assert!(
            Cert::from_bytes(relabeled.as_bytes())
                .expect("relabeled key parses")
                .is_tsk()
        );
        let smime_with_private = format!(
            "{CERT_SMIME}-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIAO3hAf144lTAVjTkht3ZwBTK0CMCCd1bI0alggneN3B\n-----END PRIVATE KEY-----\n"
        );

        for (name, key) in [
            ("pgp private block", tsk),
            ("pgp secret material", relabeled),
            ("pem private key", smime_with_private),
        ] {
            assert!(parse(key).is_err(), "{name} must be rejected");
        }
    }

    #[test]
    fn smime_trailing_data_is_rejected() {
        let der = parse_ok(CERT_SMIME).certs[0].to_vec();
        let pem = |bytes: &[u8]| {
            format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                STANDARD.encode(bytes)
            )
        };
        assert_eq!(parse_ok(pem(&der)).certs.len(), 1);

        let mut padded = der;
        padded.extend_from_slice(b"trailing data");
        assert!(parse(pem(&padded)).is_err());
    }

    #[test]
    fn pgp_key_is_accepted() {
        let params = parse_ok(CERT_PGP);
        assert_eq!(params.method, EncryptionMethod::PGP);
        assert_eq!(params.certs.len(), 1);
        assert_eq!(&*params.certs[0], pgp_block(CERT_PGP).as_bytes());
    }

    #[test]
    fn pgp_armor_headers_are_accepted() {
        for headers in [
            "Version: GnuPG v2\nComment: GPGTools - https://gpgtools.org\n",
            "Comment: some-tool with-hyphens-in-it\n",
            "Version: OpenPGP.js v4.10.10\nComment: https://openpgpjs.org\n",
        ] {
            let key = with_headers(CERT_PGP, headers);
            assert_ne!(key, CERT_PGP);
            let params = parse_ok(key.as_str());
            assert_eq!(params.method, EncryptionMethod::PGP, "{headers}");
            assert_eq!(params.certs.len(), 1, "{headers}");
            assert_eq!(&*params.certs[0], pgp_block(&key).as_bytes(), "{headers}");
        }
    }

    #[test]
    fn concatenated_pgp_keys_are_validated_individually() {
        let second = second_pgp_key();
        let joined = format!("{CERT_PGP}\n{second}");
        let params = parse_ok(joined);
        assert_eq!(params.method, EncryptionMethod::PGP);
        assert_eq!(params.certs.len(), 2);
        assert_eq!(&*params.certs[0], pgp_block(CERT_PGP).as_bytes());
        assert_eq!(&*params.certs[1], second.as_bytes());

        let lines = second.lines().collect::<Vec<_>>();
        let truncated_second = format!(
            "{}\n{PGP_END}",
            lines
                .iter()
                .take(lines.len() / 2)
                .copied()
                .collect::<Vec<_>>()
                .join("\n")
        );
        assert!(parse(truncated_second.as_str()).is_err());
        assert!(parse(format!("{CERT_PGP}{truncated_second}")).is_err());
    }

    #[test]
    fn crlf_line_endings_are_accepted() {
        let key = with_headers(CERT_PGP, "Comment: crlf-test\n").replace('\n', "\r\n");
        assert_eq!(parse_ok(key).method, EncryptionMethod::PGP);
        assert_eq!(
            parse_ok(CERT_SMIME.replace('\n', "\r\n")).method,
            EncryptionMethod::SMIME
        );
    }

    #[test]
    fn malformed_keys_are_rejected() {
        let lines = CERT_PGP.lines().collect::<Vec<_>>();
        let truncated = format!(
            "{}\n{PGP_END}",
            lines
                .iter()
                .take(lines.len() / 2)
                .copied()
                .collect::<Vec<_>>()
                .join("\n")
        );
        let garbage = format!("{PGP_BEGIN}\nthis is not base64 !!!\n{PGP_END}");
        let unterminated = CERT_PGP.replace(PGP_END, "");
        let mismatched = CERT_PGP.replace(PGP_END, "-----END CERTIFICATE-----\n");
        let missing_end = CERT_PGP.replace(PGP_END, "") + CERT_SMIME;
        let smime_garbage =
            "-----BEGIN CERTIFICATE-----\nnot a certificate\n-----END CERTIFICATE-----\n";
        let smime_headers = CERT_SMIME.replacen(
            "-----BEGIN CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\n",
            1,
        );

        for (name, key) in [
            ("truncated", truncated),
            ("garbage", garbage),
            ("unterminated", unterminated),
            ("mismatched end", mismatched),
            ("missing end", missing_end),
            ("text before", format!("Here is my key:\n{CERT_PGP}")),
            ("text after", format!("{CERT_PGP}Regards\n")),
            (
                "text between",
                format!("{CERT_PGP}and\n{}", second_pgp_key()),
            ),
            ("plain text", "not a key at all\n".to_string()),
            ("smime garbage", smime_garbage.to_string()),
            ("smime headers", smime_headers),
            (
                "unknown block only",
                "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n".to_string(),
            ),
            (
                "empty label",
                "-----BEGIN -----\nAAAA\n-----END -----\n".to_string(),
            ),
            ("mixed", CERT_MIXED.to_string()),
        ] {
            assert!(parse(key).is_err(), "{name} must be rejected");
        }
    }

    #[test]
    fn empty_key_is_absent() {
        for key in ["", "\n", "  \r\n\t\n"] {
            assert!(parse(key).expect("empty key parses").is_none());
        }
    }

    #[test]
    fn smime_certificates_are_unchanged() {
        let params = parse_ok(CERT_SMIME);
        assert_eq!(params.method, EncryptionMethod::SMIME);
        let expected = CERT_SMIME
            .split("-----BEGIN CERTIFICATE-----\n")
            .filter_map(|block| block.split_once("-----END CERTIFICATE-----"))
            .map(|(body, _)| LENIENT.decode(body).expect("base64"))
            .collect::<Vec<_>>();
        assert_eq!(expected.len(), 3);
        assert_eq!(
            params
                .certs
                .iter()
                .map(|cert| cert.to_vec())
                .collect::<Vec<_>>(),
            expected
        );
    }
}
