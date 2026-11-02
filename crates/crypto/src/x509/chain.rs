/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    backend::hash::HashAlgorithm,
    error::ChainError,
    x509::{
        cert::{Certificate, KU_CRL_SIGN, KU_KEY_CERT_SIGN, signature_hash},
        crl::Crl,
        names::NameConstraints,
        trust::{Anchor, TrustAnchors},
    },
};

const MAX_PATH: usize = 6;
const MAX_TRACKED_URLS: usize = 8;
const MAX_SIGNATURE_CHECKS: usize = 48;

#[derive(Debug, Clone, Copy)]
pub struct TrustContext<'x> {
    pub anchors: &'x TrustAnchors,
    pub intermediates: &'x [&'x [u8]],
    pub crls: &'x [Crl],
    pub now: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChainStatus {
    Valid,
    RevocationUnknown,
    Expired,
    Revoked,
    Untrusted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainVerdict {
    pub status: ChainStatus,
    pub crl_urls: Vec<Box<str>>,
    pub issuer_urls: Vec<Box<str>>,
}

enum Revocation {
    Good,
    Revoked,
    Unknown,
}

struct Search<'c, 'x> {
    ctx: &'c TrustContext<'x>,
    path: [Option<Certificate<'x>>; MAX_PATH],
    budget: usize,
    best: Option<(ChainStatus, Vec<Box<str>>)>,
    issuer_urls: Vec<Box<str>>,
}

fn push_unique(urls: &mut Vec<Box<str>>, url: &str) {
    if urls.len() < MAX_TRACKED_URLS && !urls.iter().any(|known| known.as_ref() == url) {
        urls.push(url.into());
    }
}

fn key_ids_match(child: &Certificate<'_>, issuer: &Certificate<'_>) -> bool {
    match (child.extensions.aki, issuer.extensions.ski) {
        (Some(aki), Some(ski)) => aki == ski,
        _ => true,
    }
}

pub fn verify_smime_chain(leaf: &[u8], ctx: &TrustContext<'_>) -> Result<ChainVerdict, ChainError> {
    let leaf = Certificate::parse(leaf).map_err(|_| ChainError::MalformedCertificate)?;
    if leaf.extensions.unknown_critical {
        return Err(ChainError::UnsupportedCriticalExtension);
    }
    if !leaf.has_email_protection() {
        return Err(ChainError::NoEmailProtection);
    }
    if ctx.anchors.contains(&leaf) {
        let status = if leaf.is_valid_at(ctx.now) {
            ChainStatus::Valid
        } else {
            ChainStatus::Expired
        };
        return Ok(ChainVerdict {
            status,
            crl_urls: Vec::new(),
            issuer_urls: Vec::new(),
        });
    }
    let mut path = [None; MAX_PATH];
    path[0] = Some(leaf);
    let mut search = Search {
        ctx,
        path,
        budget: MAX_SIGNATURE_CHECKS,
        best: None,
        issuer_urls: Vec::new(),
    };
    search.extend(1);
    Ok(match search.best {
        Some((status, crl_urls)) => ChainVerdict {
            status,
            crl_urls,
            issuer_urls: Vec::new(),
        },
        None => ChainVerdict {
            status: ChainStatus::Untrusted,
            crl_urls: Vec::new(),
            issuer_urls: search.issuer_urls,
        },
    })
}

impl<'x> Search<'_, 'x> {
    fn below(&self, depth: usize) -> impl Iterator<Item = &Certificate<'x>> {
        self.path.get(..depth).unwrap_or_default().iter().flatten()
    }

    fn intermediates_below(&self, depth: usize) -> u32 {
        self.below(depth)
            .skip(1)
            .filter(|cert| !cert.is_self_issued())
            .count() as u32
    }

    fn signs(&mut self, issuer: &Certificate<'_>, child: &Certificate<'_>) -> bool {
        if self.budget == 0 {
            return false;
        }
        self.budget -= 1;
        signature_hash(&child.signature_algorithm) != Some(HashAlgorithm::Sha1)
            && child.verify_signed_by(&issuer.spki)
    }

    fn constraints_permit(&self, issuer: &Certificate<'_>, depth: usize) -> bool {
        let Some(content) = issuer.extensions.name_constraints else {
            return true;
        };
        let Ok(constraints) = NameConstraints::parse(content) else {
            return false;
        };
        self.below(depth)
            .enumerate()
            .all(|(index, cert)| (index > 0 && cert.is_self_issued()) || constraints.permits(cert))
    }

    fn path_len_ok(&self, issuer: &Certificate<'_>, depth: usize) -> bool {
        issuer
            .extensions
            .basic_constraints
            .and_then(|bc| bc.path_len)
            .is_none_or(|max| self.intermediates_below(depth) <= max)
    }

    fn intermediate_ok(&self, candidate: &Certificate<'_>, depth: usize) -> bool {
        !candidate.extensions.unknown_critical
            && candidate.is_ca()
            && candidate
                .extensions
                .key_usage
                .is_none_or(|bits| bits & KU_KEY_CERT_SIGN != 0)
            && candidate.has_email_protection()
            && self.path_len_ok(candidate, depth)
            && self.constraints_permit(candidate, depth)
    }

    fn anchor_ok(&self, anchor: &Anchor<'_>, depth: usize) -> bool {
        let leaf_issued = self.path[0].map_or(0, |leaf| leaf.not_before);
        anchor
            .distrust_after
            .is_none_or(|distrust| leaf_issued <= distrust)
            && self.path_len_ok(&anchor.cert, depth)
            && self.constraints_permit(&anchor.cert, depth)
    }

    fn extend(&mut self, depth: usize) -> bool {
        let Some(Some(child)) = self.path.get(depth - 1).copied() else {
            return false;
        };
        let ctx = self.ctx;
        let mut issuer_seen = false;
        for anchor in ctx.anchors.find(child.issuer) {
            issuer_seen = true;
            if !key_ids_match(&child, &anchor.cert)
                || !self.anchor_ok(&anchor, depth)
                || !self.signs(&anchor.cert, &child)
            {
                continue;
            }
            let (status, urls) = self.evaluate(depth, &anchor.cert);
            if self.best.as_ref().is_none_or(|(best, _)| status < *best) {
                self.best = Some((status, urls));
            }
            if status == ChainStatus::Valid {
                return true;
            }
        }
        if depth < MAX_PATH {
            for der in ctx.intermediates {
                let Ok(candidate) = Certificate::parse(der) else {
                    continue;
                };
                if candidate.subject != child.issuer {
                    continue;
                }
                issuer_seen = true;
                if self.below(depth).any(|known| known.raw == candidate.raw)
                    || !key_ids_match(&child, &candidate)
                    || !self.intermediate_ok(&candidate, depth)
                    || !self.signs(&candidate, &child)
                {
                    continue;
                }
                if let Some(slot) = self.path.get_mut(depth) {
                    *slot = Some(candidate);
                }
                if self.extend(depth + 1) {
                    return true;
                }
                if let Some(slot) = self.path.get_mut(depth) {
                    *slot = None;
                }
            }
        }
        if !issuer_seen {
            for url in child.ca_issuer_urls() {
                push_unique(&mut self.issuer_urls, url);
            }
        }
        false
    }

    fn revocation(&self, cert: &Certificate<'_>, issuer: &Certificate<'_>) -> Revocation {
        let mut result = Revocation::Unknown;
        if issuer
            .extensions
            .key_usage
            .is_some_and(|bits| bits & KU_CRL_SIGN == 0)
        {
            return result;
        }
        for crl in self.ctx.crls {
            if crl.covers(cert) && crl.is_current(self.ctx.now) && crl.verify(&issuer.spki) {
                if crl.is_revoked(cert.serial) {
                    return Revocation::Revoked;
                }
                result = Revocation::Good;
            }
        }
        result
    }

    fn evaluate(&self, depth: usize, anchor: &Certificate<'_>) -> (ChainStatus, Vec<Box<str>>) {
        let mut expired = false;
        let mut revoked = false;
        let mut crl_urls = Vec::new();
        let mut certs = self.below(depth).peekable();
        while let Some(cert) = certs.next() {
            let issuer = certs.peek().copied().unwrap_or(anchor);
            expired |= !cert.is_valid_at(self.ctx.now);
            match self.revocation(cert, issuer) {
                Revocation::Good => {}
                Revocation::Revoked => revoked = true,
                Revocation::Unknown => {
                    for url in cert.crl_urls() {
                        push_unique(&mut crl_urls, url);
                    }
                }
            }
        }
        let status = if revoked {
            ChainStatus::Revoked
        } else if expired {
            ChainStatus::Expired
        } else if !crl_urls.is_empty() {
            ChainStatus::RevocationUnknown
        } else {
            ChainStatus::Valid
        };
        if status != ChainStatus::RevocationUnknown {
            crl_urls.clear();
        }
        (status, crl_urls)
    }
}
