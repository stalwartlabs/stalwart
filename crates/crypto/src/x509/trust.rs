/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    error::ChainError,
    x509::{
        cert::Certificate,
        recipient::{certificates, decode_certificates},
    },
};

static EMBEDDED: &[u8] = include_bytes!("../../resources/email-anchors.bin");
const MAGIC: &[u8; 4] = b"SWTA";
const MAX_CUSTOM_ANCHORS: usize = 256;

#[derive(Debug, Clone, Copy)]
pub(crate) struct Anchor<'x> {
    pub cert: Certificate<'x>,
    pub distrust_after: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct TrustAnchor {
    pub subject: String,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Default)]
pub struct TrustAnchors {
    embedded: bool,
    custom: Vec<Box<[u8]>>,
}

fn be_u32(data: &[u8]) -> Option<usize> {
    data.first_chunk::<4>()
        .map(|bytes| u32::from_be_bytes(*bytes) as usize)
}

pub(crate) fn embedded_count() -> usize {
    EMBEDDED
        .strip_prefix(MAGIC)
        .and_then(be_u32)
        .unwrap_or_default()
}

fn embedded_record(index: usize) -> Option<(u64, &'static [u8])> {
    let table = EMBEDDED.get(MAGIC.len() + 4..)?;
    let offset = be_u32(table.get(index.checked_mul(4)?..)?)?;
    let record = EMBEDDED.get(offset..)?;
    let (distrust, rest) = record.split_first_chunk::<8>()?;
    let (len, rest) = rest.split_first_chunk::<4>()?;
    let der = rest.get(..u32::from_be_bytes(*len) as usize)?;
    Some((u64::from_be_bytes(*distrust), der))
}

pub(crate) fn embedded_anchor(index: usize) -> Option<Anchor<'static>> {
    let (distrust, der) = embedded_record(index)?;
    Some(Anchor {
        cert: Certificate::parse(der).ok()?,
        distrust_after: (distrust != 0).then_some(distrust),
    })
}

impl<'x> Anchor<'x> {
    fn shorten<'s>(self) -> Anchor<'s>
    where
        'x: 's,
    {
        self
    }
}

impl TrustAnchors {
    pub fn embedded() -> Self {
        TrustAnchors {
            embedded: true,
            custom: Vec::new(),
        }
    }

    pub fn empty() -> Self {
        TrustAnchors::default()
    }

    pub fn add(&mut self, input: &[u8]) -> Result<usize, ChainError> {
        let der = decode_certificates(input).map_err(|_| ChainError::MalformedCertificate)?;
        let mut added = 0;
        for cert in certificates(&der) {
            let cert = cert.map_err(|_| ChainError::MalformedCertificate)?;
            if self.custom.len() >= MAX_CUSTOM_ANCHORS {
                return Err(ChainError::TooManyAnchors);
            }
            if !self.custom.iter().any(|known| known.as_ref() == cert.raw) {
                self.custom.push(cert.raw.into());
                added += 1;
            }
        }
        Ok(added)
    }

    pub fn inspect(input: &[u8]) -> Result<TrustAnchor, ChainError> {
        let der = decode_certificates(input).map_err(|_| ChainError::MalformedCertificate)?;
        let mut certs = certificates(&der);
        let cert = certs
            .next()
            .ok_or(ChainError::MalformedCertificate)?
            .map_err(|_| ChainError::MalformedCertificate)?;
        if certs.next().is_some() || !cert.is_ca() {
            return Err(ChainError::MalformedCertificate);
        }
        Ok(TrustAnchor {
            subject: cert.display_name(),
            expires_at: cert.not_after,
        })
    }

    pub fn len(&self) -> usize {
        self.custom.len() + if self.embedded { embedded_count() } else { 0 }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub(crate) fn find<'s>(&'s self, subject: &'s [u8]) -> impl Iterator<Item = Anchor<'s>> + 's {
        let custom = self
            .custom
            .iter()
            .filter_map(|der| Certificate::parse(der).ok())
            .filter(move |cert| cert.subject == subject)
            .map(|cert| Anchor {
                cert,
                distrust_after: None,
            });
        let embedded = if self.embedded {
            embedded_range(subject)
        } else {
            0..0
        };
        custom.chain(
            embedded
                .filter_map(|index| embedded_anchor(index).map(Anchor::shorten))
                .filter(move |anchor| anchor.cert.subject == subject),
        )
    }

    pub(crate) fn contains(&self, cert: &Certificate<'_>) -> bool {
        self.find(cert.subject)
            .any(|anchor| anchor.cert.raw == cert.raw)
    }
}

fn embedded_subject(index: usize) -> &'static [u8] {
    embedded_record(index)
        .and_then(|(_, der)| Certificate::parse(der).ok())
        .map(|cert| cert.subject)
        .unwrap_or_default()
}

fn lower_bound(count: usize, before: impl Fn(&[u8]) -> bool) -> usize {
    let (mut low, mut high) = (0, count);
    while low < high {
        let mid = low + (high - low) / 2;
        if before(embedded_subject(mid)) {
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    low
}

fn embedded_range(subject: &[u8]) -> std::ops::Range<usize> {
    let count = embedded_count();
    lower_bound(count, |s| s < subject)..lower_bound(count, |s| s <= subject)
}
