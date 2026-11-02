/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    backend::{
        aes::AesKeySize,
        agree::Curve,
        hash::HashAlgorithm,
        kem::MlKem,
        verify::{EcCurve, MlDsa},
    },
    error::KeyError,
    pgp::packet::Fields,
    types::Fingerprint,
};

pub(crate) const ALG_RSA: u8 = 1;
pub(crate) const ALG_RSA_ENCRYPT: u8 = 2;
pub(crate) const ALG_RSA_SIGN: u8 = 3;
pub(crate) const ALG_ELGAMAL: u8 = 16;
pub(crate) const ALG_DSA: u8 = 17;
pub(crate) const ALG_ECDH: u8 = 18;
pub(crate) const ALG_ECDSA: u8 = 19;
pub(crate) const ALG_ELGAMAL_SIGN: u8 = 20;
pub(crate) const ALG_EDDSA_LEGACY: u8 = 22;
pub(crate) const ALG_X25519: u8 = 25;
pub(crate) const ALG_X448: u8 = 26;
pub(crate) const ALG_ED25519: u8 = 27;
pub(crate) const ALG_ED448: u8 = 28;
pub(crate) const ALG_MLDSA65_ED25519: u8 = 30;
pub(crate) const ALG_MLDSA87_ED448: u8 = 31;
pub(crate) const ALG_SLHDSA_FIRST: u8 = 32;
pub(crate) const ALG_SLHDSA_LAST: u8 = 34;
pub(crate) const ALG_MLKEM768_X25519: u8 = 35;
pub(crate) const ALG_MLKEM1024_X448: u8 = 36;

pub(crate) const SYM_AES128: u8 = 7;
pub(crate) const SYM_AES192: u8 = 8;
pub(crate) const SYM_AES256: u8 = 9;

const OID_P256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const OID_P384: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x22];
const OID_P521: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x23];
const OID_CURVE25519_LEGACY: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01];
const OID_ED25519_LEGACY: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];
const OID_BRAINPOOL_PREFIX: &[u8] = &[0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01];

const ED25519_LEN: usize = 32;
const ED448_LEN: usize = 57;
const X25519_LEN: usize = 32;
const X448_LEN: usize = 56;
const NATIVE_POINT_PREFIX: u8 = 0x40;
const MLDSA65_PUBLIC_LEN: usize = 1952;
const MLDSA87_PUBLIC_LEN: usize = 2592;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum KeyVersion {
    V4,
    V6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EcdhCurve {
    Nist(Curve),
    Curve25519Legacy,
}

impl EcdhCurve {
    pub(crate) fn oid(self) -> &'static [u8] {
        match self {
            EcdhCurve::Nist(Curve::P256) => OID_P256,
            EcdhCurve::Nist(Curve::P384) => OID_P384,
            EcdhCurve::Nist(_) => OID_P521,
            EcdhCurve::Curve25519Legacy => OID_CURVE25519_LEGACY,
        }
    }

    pub(crate) fn curve(self) -> Curve {
        match self {
            EcdhCurve::Nist(curve) => curve,
            EcdhCurve::Curve25519Legacy => Curve::X25519,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum KeyMaterial<'x> {
    Rsa {
        n: &'x [u8],
        e: &'x [u8],
    },
    Ecdsa {
        curve: EcCurve,
        point: &'x [u8],
    },
    EdDsaLegacy {
        point: &'x [u8; ED25519_LEN],
    },
    Ecdh {
        curve: EcdhCurve,
        point: &'x [u8],
        kdf_hash: HashAlgorithm,
        kek: AesKeySize,
        kdf_hash_id: u8,
        kek_id: u8,
    },
    X25519(&'x [u8; X25519_LEN]),
    X448(&'x [u8; X448_LEN]),
    Ed25519(&'x [u8; ED25519_LEN]),
    Ed448(&'x [u8; ED448_LEN]),
    MlKem {
        kem: MlKem,
        ecdh: &'x [u8],
        mlkem: &'x [u8],
    },
    MlDsa {
        dsa: MlDsa,
        eddsa: &'x [u8],
        mldsa: &'x [u8],
    },
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct KeyPacket<'x> {
    pub version: KeyVersion,
    pub created: u32,
    pub algorithm: u8,
    pub material: KeyMaterial<'x>,
    pub body: &'x [u8],
    pub fingerprint: Fingerprint,
}

pub(crate) fn hash_id(id: u8) -> Option<HashAlgorithm> {
    match id {
        2 => Some(HashAlgorithm::Sha1),
        8 => Some(HashAlgorithm::Sha256),
        9 => Some(HashAlgorithm::Sha384),
        10 => Some(HashAlgorithm::Sha512),
        11 => Some(HashAlgorithm::Sha224),
        12 => Some(HashAlgorithm::Sha3_256),
        14 => Some(HashAlgorithm::Sha3_512),
        _ => None,
    }
}

pub(crate) fn aes_id(id: u8) -> Option<AesKeySize> {
    match id {
        SYM_AES128 => Some(AesKeySize::Aes128),
        SYM_AES192 => Some(AesKeySize::Aes192),
        SYM_AES256 => Some(AesKeySize::Aes256),
        _ => None,
    }
}

pub(crate) fn aes_key_id(size: AesKeySize) -> u8 {
    match size {
        AesKeySize::Aes128 => SYM_AES128,
        AesKeySize::Aes192 => SYM_AES192,
        AesKeySize::Aes256 => SYM_AES256,
    }
}

fn parse_oid(fields: &mut Fields<'_>) -> Result<&'static [u8], KeyError> {
    let oid = fields.short_bytes()?;
    [
        OID_P256,
        OID_P384,
        OID_P521,
        OID_CURVE25519_LEGACY,
        OID_ED25519_LEGACY,
    ]
    .into_iter()
    .find(|known| *known == oid)
    .ok_or(if oid.starts_with(OID_BRAINPOOL_PREFIX) {
        KeyError::Brainpool
    } else {
        KeyError::UnsupportedKeyAlgorithm
    })
}

fn native_point(point: &[u8]) -> Result<&[u8; 32], KeyError> {
    match point.split_first() {
        Some((&NATIVE_POINT_PREFIX, rest)) => {
            rest.try_into().map_err(|_| KeyError::MalformedPacket)
        }
        _ => Err(KeyError::MalformedPacket),
    }
}

fn parse_material<'x>(
    algorithm: u8,
    fields: &mut Fields<'x>,
    version: KeyVersion,
) -> Result<KeyMaterial<'x>, KeyError> {
    Ok(match algorithm {
        ALG_RSA | ALG_RSA_ENCRYPT | ALG_RSA_SIGN => KeyMaterial::Rsa {
            n: fields.mpi()?,
            e: fields.mpi()?,
        },
        ALG_ECDSA => {
            let curve = match parse_oid(fields)? {
                OID_P256 => EcCurve::P256,
                OID_P384 => EcCurve::P384,
                OID_P521 => EcCurve::P521,
                _ => return Err(KeyError::UnsupportedKeyAlgorithm),
            };
            KeyMaterial::Ecdsa {
                curve,
                point: fields.mpi()?,
            }
        }
        ALG_EDDSA_LEGACY => {
            if parse_oid(fields)? != OID_ED25519_LEGACY || version == KeyVersion::V6 {
                return Err(KeyError::UnsupportedKeyAlgorithm);
            }
            KeyMaterial::EdDsaLegacy {
                point: native_point(fields.mpi()?)?,
            }
        }
        ALG_ECDH => {
            let curve = match parse_oid(fields)? {
                OID_P256 => EcdhCurve::Nist(Curve::P256),
                OID_P384 => EcdhCurve::Nist(Curve::P384),
                OID_P521 => EcdhCurve::Nist(Curve::P521),
                OID_CURVE25519_LEGACY if version == KeyVersion::V4 => EcdhCurve::Curve25519Legacy,
                _ => return Err(KeyError::UnsupportedKeyAlgorithm),
            };
            let point = fields.mpi()?;
            let point = match curve {
                EcdhCurve::Curve25519Legacy => native_point(point)?.as_slice(),
                EcdhCurve::Nist(_) => point,
            };
            let kdf = fields.short_bytes()?;
            let [1, kdf_hash_id, kek_id] = kdf else {
                return Err(KeyError::MalformedPacket);
            };
            KeyMaterial::Ecdh {
                curve,
                point,
                kdf_hash: hash_id(*kdf_hash_id)
                    .filter(|h| {
                        !matches!(
                            h,
                            HashAlgorithm::Sha1 | HashAlgorithm::Sha3_256 | HashAlgorithm::Sha3_512
                        )
                    })
                    .ok_or(KeyError::UnsupportedKeyAlgorithm)?,
                kek: aes_id(*kek_id).ok_or(KeyError::UnsupportedKeyAlgorithm)?,
                kdf_hash_id: *kdf_hash_id,
                kek_id: *kek_id,
            }
        }
        ALG_X25519 => KeyMaterial::X25519(
            fields
                .bytes(X25519_LEN)?
                .try_into()
                .map_err(|_| KeyError::MalformedPacket)?,
        ),
        ALG_X448 => KeyMaterial::X448(
            fields
                .bytes(X448_LEN)?
                .try_into()
                .map_err(|_| KeyError::MalformedPacket)?,
        ),
        ALG_ED25519 => KeyMaterial::Ed25519(
            fields
                .bytes(ED25519_LEN)?
                .try_into()
                .map_err(|_| KeyError::MalformedPacket)?,
        ),
        ALG_ED448 => KeyMaterial::Ed448(
            fields
                .bytes(ED448_LEN)?
                .try_into()
                .map_err(|_| KeyError::MalformedPacket)?,
        ),
        ALG_MLKEM768_X25519 => KeyMaterial::MlKem {
            kem: MlKem::MlKem768,
            ecdh: fields.bytes(X25519_LEN)?,
            mlkem: fields.bytes(MlKem::MlKem768.public_len())?,
        },
        ALG_MLKEM1024_X448 if version == KeyVersion::V6 => KeyMaterial::MlKem {
            kem: MlKem::MlKem1024,
            ecdh: fields.bytes(X448_LEN)?,
            mlkem: fields.bytes(MlKem::MlKem1024.public_len())?,
        },
        ALG_MLDSA65_ED25519 if version == KeyVersion::V6 => KeyMaterial::MlDsa {
            dsa: MlDsa::MlDsa65,
            eddsa: fields.bytes(ED25519_LEN)?,
            mldsa: fields.bytes(MLDSA65_PUBLIC_LEN)?,
        },
        ALG_MLDSA87_ED448 if version == KeyVersion::V6 => KeyMaterial::MlDsa {
            dsa: MlDsa::MlDsa87,
            eddsa: fields.bytes(ED448_LEN)?,
            mldsa: fields.bytes(MLDSA87_PUBLIC_LEN)?,
        },
        ALG_ELGAMAL | ALG_ELGAMAL_SIGN => return Err(KeyError::Elgamal),
        ALG_DSA | ALG_SLHDSA_FIRST..=ALG_SLHDSA_LAST => {
            return Err(KeyError::UnsupportedPrimaryAlgorithm);
        }
        _ => return Err(KeyError::UnsupportedKeyAlgorithm),
    })
}

impl<'x> KeyPacket<'x> {
    pub(crate) fn parse(body: &'x [u8]) -> Result<Self, KeyError> {
        let mut fields = Fields::new(body);
        let version = match fields.u8()? {
            4 => KeyVersion::V4,
            6 => KeyVersion::V6,
            _ => return Err(KeyError::UnsupportedKeyVersion),
        };
        let created = fields.u32()?;
        let algorithm = fields.u8()?;
        let material = if version == KeyVersion::V6 {
            let len = fields.u32()? as usize;
            let mut material_fields = Fields::new(fields.bytes(len)?);
            let material = parse_material(algorithm, &mut material_fields, version)?;
            if !material_fields.is_empty() {
                return Err(KeyError::MalformedPacket);
            }
            material
        } else {
            parse_material(algorithm, &mut fields, version)?
        };
        if !fields.is_empty() {
            return Err(KeyError::MalformedPacket);
        }
        Ok(KeyPacket {
            version,
            created,
            algorithm,
            material,
            body,
            fingerprint: fingerprint(version, body),
        })
    }

    pub(crate) fn key_id(&self) -> [u8; 8] {
        let mut id = [0u8; 8];
        match &self.fingerprint {
            Fingerprint::V4(fp) => id.copy_from_slice(&fp[12..]),
            Fingerprint::V6(fp) | Fingerprint::X509Sha256(fp) => id.copy_from_slice(&fp[..8]),
        }
        id
    }

    pub(crate) fn hash_into(&self, hasher: &mut crate::backend::hash::Hasher) {
        hash_key_body(self.version, self.body, hasher);
    }
}

pub(crate) fn hash_key_body(
    version: KeyVersion,
    body: &[u8],
    hasher: &mut crate::backend::hash::Hasher,
) {
    match version {
        KeyVersion::V4 => {
            hasher.update(&[0x99]);
            hasher.update(&(body.len() as u16).to_be_bytes());
        }
        KeyVersion::V6 => {
            hasher.update(&[0x9B]);
            hasher.update(&(body.len() as u32).to_be_bytes());
        }
    }
    hasher.update(body);
}

fn fingerprint(version: KeyVersion, body: &[u8]) -> Fingerprint {
    let alg = match version {
        KeyVersion::V4 => HashAlgorithm::Sha1,
        KeyVersion::V6 => HashAlgorithm::Sha256,
    };
    let mut hasher = alg.hasher();
    hash_key_body(version, body, &mut hasher);
    let digest = hasher.finish();
    match version {
        KeyVersion::V4 => {
            let mut fp = [0u8; 20];
            fp.copy_from_slice(digest.as_ref());
            Fingerprint::V4(fp)
        }
        KeyVersion::V6 => {
            let mut fp = [0u8; 32];
            fp.copy_from_slice(digest.as_ref());
            Fingerprint::V6(fp)
        }
    }
}
