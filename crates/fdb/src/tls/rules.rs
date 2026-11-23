/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::error::TlsError;
use x509_parser::{
    asn1_rs::{Any, Oid},
    certificate::X509Certificate,
    extensions::GeneralName,
    oid_registry::{
        OID_DOMAIN_COMPONENT, OID_USERID, OID_X509_COMMON_NAME, OID_X509_COUNTRY_NAME,
        OID_X509_LOCALITY_NAME, OID_X509_ORGANIZATION_NAME, OID_X509_ORGANIZATIONAL_UNIT,
        OID_X509_STATE_OR_PROVINCE_NAME,
    },
    prelude::FromDer,
    x509::X509Name,
};

const CHECK_PREFIX: &[u8] = b"Check.";
const TAG_UTF8_STRING: u32 = 12;
const TAG_UNIVERSAL_STRING: u32 = 28;
const TAG_BMP_STRING: u32 = 30;
const SAN_TAG_EMAIL: u32 = 1;
const SAN_TAG_DNS: u32 = 2;
const SAN_TAG_URI: u32 = 6;
const SAN_TAG_IP: u32 = 7;

#[derive(Debug, Default)]
pub(crate) struct Policy {
    rules: Box<[Rule]>,
    accept_any: bool,
}

#[derive(Debug, Default)]
struct Rule {
    subject: Vec<Criterion>,
    issuer: Vec<Criterion>,
    root: Vec<Criterion>,
}

#[derive(Debug)]
struct Criterion {
    field: Field,
    value: Box<[u8]>,
    match_type: MatchType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    Country,
    CommonName,
    Locality,
    State,
    Organization,
    OrganizationalUnit,
    UserId,
    DomainComponent,
    SubjectAltName,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MatchType {
    Exact,
    Prefix,
    Suffix,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    Subject,
    Issuer,
    Root,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Check {
    Valid,
    Unexpired,
}

impl Policy {
    pub(crate) fn parse(verify_peers: &[Box<str>]) -> Result<Self, TlsError> {
        let mut rules = Vec::new();
        let mut accept_any = false;
        for setting in verify_peers {
            let mut escaped = false;
            for text in setting.as_bytes().split(|&byte| {
                let split = byte == b'|' && !escaped;
                escaped = byte == b'\\' && !escaped;
                split
            }) {
                let (rule, verify_cert) =
                    Rule::parse(text).ok_or_else(|| TlsError::VerifyPeers {
                        rule: setting.clone(),
                    })?;
                accept_any |= !verify_cert;
                rules.push(rule);
            }
        }
        Ok(Self {
            rules: rules.into_boxed_slice(),
            accept_any,
        })
    }

    pub(crate) fn needs_root(&self) -> bool {
        !self.accept_any && self.rules.iter().any(|rule| !rule.root.is_empty())
    }

    pub(crate) fn accepts(&self, leaf: &[u8], root: Option<&[u8]>) -> bool {
        if self.rules.is_empty() || self.accept_any {
            return true;
        }
        let Ok((_, leaf)) = X509Certificate::from_der(leaf) else {
            return false;
        };
        let root = root.and_then(|root| X509Certificate::from_der(root).ok().map(|(_, cert)| cert));
        let mut scratch = Vec::new();
        self.rules
            .iter()
            .any(|rule| rule.matches(&leaf, root.as_ref(), &mut scratch))
    }
}

impl Rule {
    fn parse(mut rest: &[u8]) -> Option<(Self, bool)> {
        let mut rule = Self::default();
        let mut verify_cert = true;
        while !rest.is_empty() {
            let (term, after) = split_byte(rest, b'=')?;
            let (term, match_type) = match term.split_last() {
                Some((b'>', term)) => (term, MatchType::Prefix),
                Some((b'<', term)) => (term, MatchType::Suffix),
                _ => (term, MatchType::Exact),
            };
            if let Some(check) = term.strip_prefix(CHECK_PREFIX) {
                let (&value, tail) = after.split_first()?;
                rest = match tail.split_first() {
                    None => &[],
                    Some((b',', tail)) => tail,
                    Some(_) => return None,
                };
                if match_type != MatchType::Exact {
                    return None;
                }
                let check = hashify::map!(check, Check, "Valid" => Check::Valid, "Unexpired" => Check::Unexpired)?;
                let enabled = match value {
                    b'0' => false,
                    b'1' => true,
                    _ => return None,
                };
                if *check == Check::Valid {
                    verify_cert = enabled;
                }
            } else {
                let (scope, field) = match split_byte(term, b'.') {
                    Some((scope, field)) => (
                        *hashify::map!(
                            scope,
                            Scope,
                            "S" => Scope::Subject,
                            "Subject" => Scope::Subject,
                            "I" => Scope::Issuer,
                            "Issuer" => Scope::Issuer,
                            "R" => Scope::Root,
                            "Root" => Scope::Root,
                        )?,
                        field,
                    ),
                    None => (Scope::Subject, term),
                };
                let field = *hashify::map!(
                    field,
                    Field,
                    "C" => Field::Country,
                    "CN" => Field::CommonName,
                    "L" => Field::Locality,
                    "ST" => Field::State,
                    "O" => Field::Organization,
                    "OU" => Field::OrganizationalUnit,
                    "UID" => Field::UserId,
                    "DC" => Field::DomainComponent,
                    "subjectAltName" => Field::SubjectAltName,
                )?;
                let (value, consumed) = unescape(after);
                if consumed == 0 {
                    return None;
                }
                rest = match after.get(consumed..).and_then(<[u8]>::split_first) {
                    None => &[],
                    Some((b',', tail)) => tail,
                    Some(_) => return None,
                };
                let criterion = Criterion {
                    field,
                    value: latin1_to_utf8(&value).into_boxed_slice(),
                    match_type,
                };
                match scope {
                    Scope::Subject => rule.subject.push(criterion),
                    Scope::Issuer => rule.issuer.push(criterion),
                    Scope::Root => rule.root.push(criterion),
                }
            }
        }
        Some((rule, verify_cert))
    }

    fn matches(
        &self,
        leaf: &X509Certificate<'_>,
        root: Option<&X509Certificate<'_>>,
        scratch: &mut Vec<u8>,
    ) -> bool {
        self.subject
            .iter()
            .all(|criterion| criterion.matches(leaf, leaf.subject(), scratch))
            && self
                .issuer
                .iter()
                .all(|criterion| criterion.matches(leaf, leaf.issuer(), scratch))
            && (self.root.is_empty()
                || root.is_some_and(|root| {
                    self.root
                        .iter()
                        .all(|criterion| criterion.matches(root, root.subject(), scratch))
                }))
    }
}

impl Criterion {
    fn matches(
        &self,
        cert: &X509Certificate<'_>,
        name: &X509Name<'_>,
        scratch: &mut Vec<u8>,
    ) -> bool {
        match self.field.oid() {
            Some(oid) => self.matches_name(name, &oid, scratch),
            None => self.matches_alt_name(cert, scratch),
        }
    }

    fn matches_name(&self, name: &X509Name<'_>, oid: &Oid<'_>, scratch: &mut Vec<u8>) -> bool {
        let mut entries = name
            .iter_attributes()
            .filter(|attribute| attribute.attr_type() == oid);
        let (Some(entry), None) = (entries.next(), entries.next()) else {
            return false;
        };
        scratch.clear();
        asn1_to_utf8(entry.attr_value(), scratch) && self.compare(&self.value, scratch)
    }

    fn matches_alt_name(&self, cert: &X509Certificate<'_>, scratch: &mut Vec<u8>) -> bool {
        let Ok(Some(alt_names)) = cert.subject_alternative_name() else {
            return false;
        };
        for name in &alt_names.value.general_names {
            let (prefix, entry): (&[u8], &[u8]) = match name {
                GeneralName::RFC822Name(entry) => (b"EMAIL:", entry.as_bytes()),
                GeneralName::DNSName(entry) => (b"DNS:", entry.as_bytes()),
                GeneralName::URI(entry) => (b"URI:", entry.as_bytes()),
                GeneralName::IPAddress(_) => continue,
                GeneralName::Invalid(tag, entry) => match tag.0 {
                    SAN_TAG_EMAIL => (b"EMAIL:", *entry),
                    SAN_TAG_DNS => (b"DNS:", *entry),
                    SAN_TAG_URI => (b"URI:", *entry),
                    SAN_TAG_IP => continue,
                    _ => return false,
                },
                GeneralName::OtherName(..)
                | GeneralName::X400Address(_)
                | GeneralName::DirectoryName(_)
                | GeneralName::EDIPartyName(_)
                | GeneralName::RegisteredID(_) => return false,
            };
            let Some(criterion) = self.value.strip_prefix(prefix) else {
                continue;
            };
            scratch.clear();
            extend_latin1(scratch, entry);
            if self.compare(criterion, scratch) {
                return true;
            }
        }
        false
    }

    fn compare(&self, criterion: &[u8], entry: &[u8]) -> bool {
        !criterion.is_empty()
            && !entry.is_empty()
            && match self.match_type {
                MatchType::Exact => criterion == entry,
                MatchType::Prefix => entry.starts_with(criterion),
                MatchType::Suffix => entry.ends_with(criterion),
            }
    }
}

impl Field {
    fn oid(self) -> Option<Oid<'static>> {
        Some(match self {
            Self::Country => OID_X509_COUNTRY_NAME,
            Self::CommonName => OID_X509_COMMON_NAME,
            Self::Locality => OID_X509_LOCALITY_NAME,
            Self::State => OID_X509_STATE_OR_PROVINCE_NAME,
            Self::Organization => OID_X509_ORGANIZATION_NAME,
            Self::OrganizationalUnit => OID_X509_ORGANIZATIONAL_UNIT,
            Self::UserId => OID_USERID,
            Self::DomainComponent => OID_DOMAIN_COMPONENT,
            Self::SubjectAltName => return None,
        })
    }
}

fn split_byte(input: &[u8], byte: u8) -> Option<(&[u8], &[u8])> {
    let mut parts = input.splitn(2, |&candidate| candidate == byte);
    Some((parts.next()?, parts.next()?))
}

fn unescape(input: &[u8]) -> (Vec<u8>, usize) {
    let mut out = Vec::new();
    if matches!(input.first(), Some(b'#' | b' ')) {
        return (out, 0);
    }
    let mut spaces = 0;
    let mut rest = input;
    let end = loop {
        let Some((&byte, tail)) = rest.split_first() else {
            break input.len();
        };
        let position = input.len() - rest.len();
        match byte {
            b'\\' => match tail {
                [
                    escaped @ (b' ' | b'"' | b'#' | b'+' | b',' | b';' | b'<' | b'=' | b'>' | b'|'
                    | b'\\'),
                    more @ ..,
                ] => {
                    out.push(*escaped);
                    spaces = 0;
                    rest = more;
                }
                [high, low, more @ ..] => match (hex_value(*high), hex_value(*low)) {
                    (Some(high), Some(low)) => {
                        out.push((high << 4) | low);
                        spaces = 0;
                        rest = more;
                    }
                    _ => break position,
                },
                _ => break position,
            },
            b'"' | b'+' | b',' | b';' | b'<' | b'>' | 0 => break position,
            _ => {
                out.push(byte);
                spaces = if byte == b' ' { spaces + 1 } else { 0 };
                rest = tail;
            }
        }
    };
    out.truncate(out.len().saturating_sub(spaces));
    (out, end.saturating_sub(spaces))
}

fn hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

fn latin1_to_utf8(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    extend_latin1(&mut out, input);
    out
}

fn extend_latin1(out: &mut Vec<u8>, input: &[u8]) {
    if input.is_ascii() {
        out.extend_from_slice(input);
    } else {
        extend_chars(out, input.iter().map(|&byte| Some(char::from(byte))));
    }
}

fn extend_chars(out: &mut Vec<u8>, chars: impl Iterator<Item = Option<char>>) -> bool {
    let mut buf = [0u8; 4];
    for ch in chars {
        let Some(ch) = ch else {
            return false;
        };
        out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
    }
    true
}

fn asn1_to_utf8(value: &Any<'_>, out: &mut Vec<u8>) -> bool {
    let data = value.data;
    let converted = match value.header.tag().0 {
        TAG_UTF8_STRING => {
            let valid = std::str::from_utf8(data).is_ok();
            if valid {
                out.extend_from_slice(data);
            }
            valid
        }
        18..=20 | 22..=24 | 26 => {
            extend_latin1(out, data);
            true
        }
        TAG_UNIVERSAL_STRING => {
            let (chars, rest) = data.as_chunks::<4>();
            rest.is_empty()
                && extend_chars(
                    out,
                    chars
                        .iter()
                        .map(|bytes| char::from_u32(u32::from_be_bytes(*bytes))),
                )
        }
        TAG_BMP_STRING => {
            let (chars, rest) = data.as_chunks::<2>();
            rest.is_empty()
                && extend_chars(
                    out,
                    chars
                        .iter()
                        .map(|bytes| char::from_u32(u32::from(u16::from_be_bytes(*bytes)))),
                )
        }
        _ => false,
    };
    converted && !out.is_empty()
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/fdb/src/tls/rules/tests.rs"]
mod tests;
