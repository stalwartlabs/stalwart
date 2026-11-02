/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    backend::{
        PrimitiveError,
        hash::{HashAlgorithm, Hasher},
        verify::{MlDsa, SignatureScheme},
    },
    der::tag,
    der::writer::{
        rsa_public_key_len, tlv_len, unsigned_integer_len, write_header, write_rsa_public_key,
        write_unsigned_integer,
    },
    error::KeyError,
    pgp::{
        key::{KeyMaterial, KeyPacket, KeyVersion, hash_id},
        packet::{Fields, strip_leading_zeros},
    },
    types::Fingerprint,
};

pub(crate) const SIG_BINARY: u8 = 0x00;
pub(crate) const SIG_TEXT: u8 = 0x01;
pub(crate) const SIG_PRIMARY_BINDING: u8 = 0x19;
pub(crate) const SIG_CERT_FIRST: u8 = 0x10;
pub(crate) const SIG_CERT_LAST: u8 = 0x13;
pub(crate) const SIG_SUBKEY_BINDING: u8 = 0x18;
pub(crate) const SIG_DIRECT_KEY: u8 = 0x1F;
pub(crate) const SIG_KEY_REVOCATION: u8 = 0x20;
pub(crate) const SIG_SUBKEY_REVOCATION: u8 = 0x28;

const SHA1_CUTOFF: u32 = 1_675_209_600;
const MAX_SUBPACKET_AREA: usize = 1 << 16;
const ED25519_SIG_LEN: usize = 64;
const ED448_SIG_LEN: usize = 114;
const MLDSA65_SIG_LEN: usize = 3309;
const MLDSA87_SIG_LEN: usize = 4627;
const CRITICAL: u8 = 0x80;

pub(crate) const FEATURE_SEIPDV2: u8 = 0x08;
pub(crate) const FLAG_SIGN: u8 = 0x02;
pub(crate) const FLAG_ENCRYPT_COMMUNICATIONS: u8 = 0x04;
pub(crate) const FLAG_ENCRYPT_STORAGE: u8 = 0x08;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct SymPrefs(u8);

impl SymPrefs {
    pub(crate) const AES128: u8 = 1;
    pub(crate) const AES192: u8 = 2;
    pub(crate) const AES256: u8 = 4;

    pub(crate) fn contains(self, bit: u8) -> bool {
        self.0 & bit != 0
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct AeadPrefs {
    pairs: [(u8, u8); 6],
    len: u8,
}

impl AeadPrefs {
    fn push(&mut self, pair: (u8, u8)) {
        if self.as_slice().contains(&pair) {
            return;
        }
        if let Some(slot) = self.pairs.get_mut(usize::from(self.len)) {
            *slot = pair;
            self.len += 1;
        }
    }

    pub(crate) fn as_slice(&self) -> &[(u8, u8)] {
        &self.pairs[..usize::from(self.len)]
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct SigInfo {
    pub created: Option<u32>,
    pub sig_expires: Option<u32>,
    pub key_expires: Option<u32>,
    pub key_flags: Option<u8>,
    pub features: Option<u8>,
    pub sym_prefs: Option<SymPrefs>,
    pub aead_prefs: Option<AeadPrefs>,
    pub primary_uid: bool,
    pub revocation_key: Option<Fingerprint>,
    pub issuer_fingerprint: Option<Fingerprint>,
    pub issuer_key_id: Option<[u8; 8]>,
    pub unknown_critical: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SigVersion {
    V4,
    V6,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Signature<'x> {
    pub version: SigVersion,
    pub sig_type: u8,
    pub pk_algorithm: u8,
    pub hash_algorithm: u8,
    pub hashed_prefix: &'x [u8],
    pub left16: [u8; 2],
    pub salt: &'x [u8],
    pub material: &'x [u8],
    pub embedded: Option<&'x [u8]>,
    pub info: SigInfo,
}

fn subpackets(mut data: &[u8]) -> impl Iterator<Item = Result<(u8, bool, &[u8]), KeyError>> {
    std::iter::from_fn(move || {
        if data.is_empty() {
            return None;
        }
        let mut fields = Fields::new(data);
        let result = (|| {
            let first = fields.u8()?;
            let len = match first {
                0..192 => usize::from(first),
                192..255 => ((usize::from(first) - 192) << 8) + usize::from(fields.u8()?) + 192,
                255 => fields.u32()? as usize,
            };
            let body = fields.bytes(len)?;
            let (type_byte, value) = body.split_first().ok_or(KeyError::MalformedPacket)?;
            Ok((type_byte & !CRITICAL, type_byte & CRITICAL != 0, value))
        })();
        data = if result.is_ok() {
            fields.remaining()
        } else {
            &[]
        };
        Some(result)
    })
}

fn be_u32(value: &[u8]) -> Result<u32, KeyError> {
    value
        .try_into()
        .map(u32::from_be_bytes)
        .map_err(|_| KeyError::MalformedPacket)
}

fn parse_fingerprint(value: &[u8]) -> Option<Fingerprint> {
    match value.split_first() {
        Some((4, fp)) => fp.try_into().ok().map(Fingerprint::V4),
        Some((6, fp)) => fp.try_into().ok().map(Fingerprint::V6),
        _ => None,
    }
}

fn parse_hashed<'x>(info: &mut SigInfo, area: &'x [u8]) -> Result<Option<&'x [u8]>, KeyError> {
    let mut embedded = None;
    for subpacket in subpackets(area) {
        let (kind, critical, value) = subpacket?;
        match kind {
            2 => info.created = Some(be_u32(value)?),
            3 => info.sig_expires = Some(be_u32(value)?).filter(|v| *v != 0),
            9 => info.key_expires = Some(be_u32(value)?).filter(|v| *v != 0),
            11 => {
                let mut prefs = SymPrefs::default();
                for alg in value {
                    prefs.0 |= match alg {
                        7 => SymPrefs::AES128,
                        8 => SymPrefs::AES192,
                        9 => SymPrefs::AES256,
                        _ => 0,
                    };
                }
                info.sym_prefs = Some(prefs);
            }
            12 => {
                if let [_class, _alg, fp @ ..] = value {
                    info.revocation_key = fp.try_into().ok().map(Fingerprint::V4);
                }
            }
            16 => info.issuer_key_id = value.try_into().ok(),
            25 => info.primary_uid = value.first().is_some_and(|v| *v != 0),
            27 => info.key_flags = Some(value.first().copied().unwrap_or(0)),
            30 => info.features = Some(value.first().copied().unwrap_or(0)),
            33 => info.issuer_fingerprint = parse_fingerprint(value),
            39 => {
                let mut prefs = AeadPrefs::default();
                let (pairs, _) = value.as_chunks::<2>();
                for [cipher, aead] in pairs {
                    if matches!(cipher, 7..=9) && matches!(aead, 2 | 3) {
                        prefs.push((*cipher, *aead));
                    }
                }
                info.aead_prefs = Some(prefs);
            }
            32 => embedded = Some(value),
            4 | 5 | 6 | 7 | 20 | 21 | 22 | 23 | 24 | 26 | 28 | 29 | 31 | 34 | 35 | 37 => {
                if critical && matches!(kind, 5 | 6 | 20 | 34 | 37) {
                    info.unknown_critical = true;
                }
            }
            _ => {
                if critical {
                    info.unknown_critical = true;
                }
            }
        }
    }
    Ok(embedded)
}

fn parse_unhashed<'x>(info: &mut SigInfo, area: &'x [u8]) -> Result<Option<&'x [u8]>, KeyError> {
    let mut embedded = None;
    for subpacket in subpackets(area) {
        let (kind, _, value) = subpacket?;
        match kind {
            32 => embedded = Some(value),
            16 if info.issuer_key_id.is_none() => info.issuer_key_id = value.try_into().ok(),
            33 if info.issuer_fingerprint.is_none() => {
                info.issuer_fingerprint = parse_fingerprint(value)
            }
            _ => {}
        }
    }
    Ok(embedded)
}

impl<'x> Signature<'x> {
    pub(crate) fn parse(body: &'x [u8]) -> Result<Self, KeyError> {
        let mut fields = Fields::new(body);
        let version = match fields.u8()? {
            4 => SigVersion::V4,
            6 => SigVersion::V6,
            _ => return Err(KeyError::UnsupportedKeyVersion),
        };
        let sig_type = fields.u8()?;
        let pk_algorithm = fields.u8()?;
        let hash_algorithm = fields.u8()?;
        let read_area = |fields: &mut Fields<'x>| -> Result<&'x [u8], KeyError> {
            let len = match version {
                SigVersion::V4 => usize::from(fields.u16()?),
                SigVersion::V6 => fields.u32()? as usize,
            };
            if len > MAX_SUBPACKET_AREA {
                return Err(KeyError::MalformedPacket);
            }
            fields.bytes(len)
        };
        let hashed = read_area(&mut fields)?;
        let hashed_prefix = &body[..body.len() - fields.remaining().len()];
        let unhashed = read_area(&mut fields)?;
        let left16 = fields.array::<2>()?;
        let salt = match version {
            SigVersion::V4 => &[][..],
            SigVersion::V6 => fields.short_bytes()?,
        };
        let mut info = SigInfo::default();
        let embedded = parse_hashed(&mut info, hashed)?.or(parse_unhashed(&mut info, unhashed)?);
        Ok(Signature {
            version,
            sig_type,
            pk_algorithm,
            hash_algorithm,
            hashed_prefix,
            left16,
            salt,
            material: fields.remaining(),
            embedded,
            info,
        })
    }

    pub(crate) fn is_issued_by(&self, key: &KeyPacket<'_>) -> bool {
        match (&self.info.issuer_fingerprint, &self.info.issuer_key_id) {
            (Some(fp), _) => *fp == key.fingerprint,
            (None, Some(id)) => *id == key.key_id(),
            (None, None) => true,
        }
    }

    pub(crate) fn hasher(&self, now: u64) -> Result<(HashAlgorithm, Hasher), KeyError> {
        let hash = hash_id(self.hash_algorithm).ok_or(KeyError::UnsupportedKeyAlgorithm)?;
        let created = self.info.created.ok_or(KeyError::NoValidSelfSignature)?;
        if self.info.unknown_critical
            || (hash == HashAlgorithm::Sha1 && created > SHA1_CUTOFF)
            || u64::from(created) > now
            || self
                .info
                .sig_expires
                .is_some_and(|exp| u64::from(created) + u64::from(exp) <= now)
        {
            return Err(KeyError::NoValidSelfSignature);
        }
        if self.version == SigVersion::V6 {
            let expected_salt = match hash {
                HashAlgorithm::Sha256 | HashAlgorithm::Sha224 | HashAlgorithm::Sha3_256 => 16,
                HashAlgorithm::Sha384 => 24,
                HashAlgorithm::Sha512 | HashAlgorithm::Sha3_512 => 32,
                HashAlgorithm::Sha1 => return Err(KeyError::NoValidSelfSignature),
            };
            if self.salt.len() != expected_salt {
                return Err(KeyError::MalformedPacket);
            }
        }
        let mut hasher = hash.hasher();
        hasher.update(self.salt);
        Ok((hash, hasher))
    }

    pub(crate) fn finish(&self, mut hasher: Hasher) -> aws_lc_rs::digest::Digest {
        hasher.update(self.hashed_prefix);
        let marker = match self.version {
            SigVersion::V4 => 4,
            SigVersion::V6 => 6,
        };
        hasher.update(&[marker, 0xFF]);
        hasher.update(&(self.hashed_prefix.len() as u32).to_be_bytes());
        hasher.finish()
    }

    pub(crate) fn verify(
        &self,
        signer: &KeyPacket<'_>,
        data: impl FnOnce(&mut Hasher),
        now: u64,
    ) -> Result<(), KeyError> {
        if self.pk_algorithm != signer.algorithm
            || (self.version == SigVersion::V6) != (signer.version == KeyVersion::V6)
        {
            return Err(KeyError::NoValidSelfSignature);
        }
        let (hash, mut hasher) = self.hasher(now)?;
        data(&mut hasher);
        let digest = self.finish(hasher);
        if digest.as_ref().get(..2) != Some(self.left16.as_slice()) {
            return Err(KeyError::NoValidSelfSignature);
        }
        verify_digest(&signer.material, hash, &digest, self.material)
            .map_err(|_| KeyError::NoValidSelfSignature)
    }
}

fn left_pad<const N: usize>(value: &[u8]) -> Result<[u8; N], PrimitiveError> {
    let value = strip_leading_zeros(value);
    let mut out = [0u8; N];
    let start = N
        .checked_sub(value.len())
        .ok_or(PrimitiveError::BadSignature)?;
    out[start..].copy_from_slice(value);
    Ok(out)
}

fn verify_digest(
    material: &KeyMaterial<'_>,
    hash: HashAlgorithm,
    digest: &aws_lc_rs::digest::Digest,
    signature: &[u8],
) -> Result<(), PrimitiveError> {
    let mut fields = Fields::new(signature);
    let mut mpi = || fields.mpi().map_err(|_| PrimitiveError::BadSignature);
    match material {
        KeyMaterial::Rsa { n, e } => {
            let n = strip_leading_zeros(n);
            let sig = strip_leading_zeros(mpi()?);
            if sig.len() > n.len() {
                return Err(PrimitiveError::BadSignature);
            }
            let mut padded = vec![0u8; n.len()];
            padded[n.len() - sig.len()..].copy_from_slice(sig);
            let mut key = Vec::with_capacity(rsa_public_key_len(n, e));
            write_rsa_public_key(&mut key, n, e);
            SignatureScheme::RsaPkcs1(hash).verify_digest(&key, digest, &padded)
        }
        KeyMaterial::Ecdsa { curve, point } => {
            let r = mpi()?;
            let s = mpi()?;
            let content = unsigned_integer_len(r) + unsigned_integer_len(s);
            let mut der = Vec::with_capacity(tlv_len(content));
            write_header(&mut der, tag::SEQUENCE, content);
            write_unsigned_integer(&mut der, r);
            write_unsigned_integer(&mut der, s);
            SignatureScheme::Ecdsa(*curve, hash).verify_digest(point, digest, &der)
        }
        KeyMaterial::EdDsaLegacy { point } => {
            let r = left_pad::<32>(mpi()?)?;
            let s = left_pad::<32>(mpi()?)?;
            let mut sig = [0u8; ED25519_SIG_LEN];
            sig[..32].copy_from_slice(&r);
            sig[32..].copy_from_slice(&s);
            SignatureScheme::Ed25519.verify(point.as_slice(), digest.as_ref(), &sig)
        }
        KeyMaterial::Ed25519(point) => {
            SignatureScheme::Ed25519.verify(point.as_slice(), digest.as_ref(), signature)
        }
        KeyMaterial::Ed448(point) => {
            SignatureScheme::Ed448.verify(point.as_slice(), digest.as_ref(), signature)
        }
        KeyMaterial::MlDsa { dsa, eddsa, mldsa } => {
            let (eddsa_scheme, eddsa_len, mldsa_len) = match dsa {
                MlDsa::MlDsa65 => (SignatureScheme::Ed25519, ED25519_SIG_LEN, MLDSA65_SIG_LEN),
                _ => (SignatureScheme::Ed448, ED448_SIG_LEN, MLDSA87_SIG_LEN),
            };
            let (eddsa_sig, mldsa_sig) = signature
                .split_at_checked(eddsa_len)
                .filter(|(_, m)| m.len() == mldsa_len)
                .ok_or(PrimitiveError::BadSignature)?;
            eddsa_scheme.verify(eddsa, digest.as_ref(), eddsa_sig)?;
            SignatureScheme::MlDsa(*dsa).verify(mldsa, digest.as_ref(), mldsa_sig)
        }
        _ => Err(PrimitiveError::UnsupportedAlgorithm),
    }
}

pub(crate) fn hash_user_id(hasher: &mut Hasher, user_id: &[u8]) {
    hasher.update(&[0xB4]);
    hasher.update(&(user_id.len() as u32).to_be_bytes());
    hasher.update(user_id);
}
