/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::Write;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OrgDn {
    org: Box<str>,
}

impl OrgDn {
    pub fn new(org: &str) -> Option<Self> {
        is_rdn(org.as_bytes()).then(|| OrgDn { org: org.into() })
    }

    pub fn as_str(&self) -> &str {
        &self.org
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnKind {
    Recipient,
    Server,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LegacyDn(Box<str>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedDn<'a> {
    pub org: &'a str,
    pub kind: DnKind,
    pub id: u64,
    pub tail: &'a str,
}

pub const GAL_DN: &str = "/";

const ORG_PREFIX: &str = "/o=";
const ADMIN_GROUP: &str = "/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)";
const RECIPIENTS: &str = "/cn=Recipients";
const SERVERS: &str = "/cn=Configuration/cn=Servers";
const OBJECT_PREFIX: &str = "/cn=";
const OBJECT_RDN: &str = "cn=";
const ID_HEX_LEN: usize = 16;
const TAIL_MAX: usize = 47;
const RDN_MAX: usize = 64;
const X500_RDN_TOTAL_MAX: usize = 256;
const X500_CONTAINER_RDN_MAX: usize = 13;
const CONTAINER_GUID_HEX_LEN: usize = 32;
const DN_CAPACITY: usize =
    ORG_PREFIX.len() + RDN_MAX + ADMIN_GROUP.len() + SERVERS.len() + OBJECT_PREFIX.len() + RDN_MAX;

impl DnKind {
    fn container(self) -> &'static str {
        match self {
            DnKind::Recipient => RECIPIENTS,
            DnKind::Server => SERVERS,
        }
    }
}

impl LegacyDn {
    pub fn for_principal(org: &OrgDn, kind: DnKind, id: u64, tail: &str) -> Self {
        let container = kind.container();
        let mut dn = String::with_capacity(DN_CAPACITY);
        dn.push_str(ORG_PREFIX);
        dn.push_str(org.as_str());
        dn.push_str(ADMIN_GROUP);
        dn.push_str(container);
        dn.push_str(OBJECT_PREFIX);
        let _ = write!(dn, "{id:016x}");
        let sanitized = tail.bytes().filter(|b| is_teletex(*b));
        let mut kept = 0usize;
        let mut pending_spaces = 0usize;
        for b in sanitized {
            if b == b' ' {
                if kept > 0 {
                    pending_spaces = pending_spaces.saturating_add(1);
                }
                continue;
            }
            if kept.saturating_add(pending_spaces) >= TAIL_MAX {
                break;
            }
            if kept == 0 {
                dn.push('-');
            }
            for _ in 0..pending_spaces {
                dn.push(' ');
            }
            kept = kept.saturating_add(pending_spaces).saturating_add(1);
            pending_spaces = 0;
            dn.push(char::from(b));
        }
        LegacyDn(dn.into_boxed_str())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn parse(&self) -> Option<ParsedDn<'_>> {
        parse_dn(self.0.as_bytes())
    }
}

pub fn parse_dn(dn: &[u8]) -> Option<ParsedDn<'_>> {
    let dn = std::str::from_utf8(dn).ok().filter(|dn| dn.is_ascii())?;
    let (head, object) = dn.rsplit_once('/')?;
    let object = strip_prefix_ci(object, OBJECT_RDN)?;
    let (head, kind) = if let Some(head) = strip_suffix_ci(head, RECIPIENTS) {
        (head, DnKind::Recipient)
    } else {
        (strip_suffix_ci(head, SERVERS)?, DnKind::Server)
    };
    let org = strip_prefix_ci(strip_suffix_ci(head, ADMIN_GROUP)?, ORG_PREFIX)?;
    if org.is_empty() {
        return None;
    }
    let (hex, tail) = object.split_at_checked(ID_HEX_LEN)?;
    if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let id = u64::from_str_radix(hex, 16).ok()?;
    let tail = match tail.strip_prefix('-') {
        Some(tail) => tail,
        None if tail.is_empty() => tail,
        None => return None,
    };
    Some(ParsedDn {
        org,
        kind,
        id,
        tail,
    })
}

pub fn validate_dn_grammar(dn: &[u8]) -> bool {
    if dn == GAL_DN.as_bytes() {
        return true;
    }
    if let Some(guid) = strip_prefix_ci_bytes(dn, b"/guid=") {
        return guid.len() == CONTAINER_GUID_HEX_LEN && guid.iter().all(u8::is_ascii_hexdigit);
    }
    let Some(rest) = dn.strip_prefix(b"/") else {
        return false;
    };
    let mut rdns = rest.split(|b| *b == b'/');
    let Some(org) = rdns.next().and_then(|r| strip_prefix_ci_bytes(r, b"o=")) else {
        return false;
    };
    if !is_rdn(org) {
        return false;
    }
    let Some(unit) = rdns.next() else {
        return true;
    };
    let Some(unit) = strip_prefix_ci_bytes(unit, b"ou=") else {
        return false;
    };
    if !is_rdn(unit) {
        return false;
    }
    let mut total = org.len().saturating_add(unit.len());
    let mut cn_count = 0usize;
    for rdn in rdns {
        let Some(rdn) = strip_prefix_ci_bytes(rdn, b"cn=") else {
            return false;
        };
        if !is_rdn(rdn) {
            return false;
        }
        cn_count = cn_count.saturating_add(1);
        total = total.saturating_add(rdn.len());
    }
    (1..=X500_CONTAINER_RDN_MAX.saturating_add(1)).contains(&cn_count)
        && total <= X500_RDN_TOTAL_MAX
}

fn is_rdn(rdn: &[u8]) -> bool {
    match (rdn.first(), rdn.last()) {
        (Some(first), Some(last)) => {
            rdn.len() <= RDN_MAX
                && *first != b' '
                && *last != b' '
                && rdn.iter().all(|b| is_teletex(*b))
        }
        _ => false,
    }
}

const fn is_teletex(b: u8) -> bool {
    matches!(
        b,
        b' ' | b'!'
            | b'"'
            | b'%'
            | b'&'
            | b'\\'
            | b'('
            | b')'
            | b'*'
            | b'+'
            | b','
            | b'-'
            | b'.'
            | b'0'..=b'9'
            | b':'
            | b'<'
            | b'='
            | b'>'
            | b'?'
            | b'@'
            | b'A'..=b'Z'
            | b'['
            | b']'
            | b'_'
            | b'a'..=b'z'
            | b'|'
    )
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let (head, rest) = s.split_at_checked(prefix.len())?;
    head.eq_ignore_ascii_case(prefix).then_some(rest)
}

fn strip_suffix_ci<'a>(s: &'a str, suffix: &str) -> Option<&'a str> {
    let (rest, tail) = s.split_at_checked(s.len().checked_sub(suffix.len())?)?;
    tail.eq_ignore_ascii_case(suffix).then_some(rest)
}

fn strip_prefix_ci_bytes<'a>(s: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    let (head, rest) = s.split_at_checked(prefix.len())?;
    head.eq_ignore_ascii_case(prefix).then_some(rest)
}
