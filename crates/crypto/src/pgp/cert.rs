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
        kem::{MlKem, MlKemPublicKey},
        rsa::{MAX_RSA_BITS, MIN_RSA_BITS, RsaPublicKey},
    },
    error::KeyError,
    pgp::{
        key::{
            ALG_ECDH, ALG_ECDSA, ALG_ED448, ALG_ED25519, ALG_EDDSA_LEGACY, ALG_MLDSA65_ED25519,
            ALG_MLDSA87_ED448, ALG_RSA, ALG_RSA_SIGN, EcdhCurve, KeyMaterial, KeyPacket,
            KeyVersion,
        },
        packet::{
            Packet, PacketReader, TAG_MARKER, TAG_PADDING, TAG_PUBLIC_KEY, TAG_PUBLIC_SUBKEY,
            TAG_SECRET_KEY, TAG_SECRET_SUBKEY, TAG_SIGNATURE, TAG_TRUST, TAG_USER_ATTRIBUTE,
            TAG_USER_ID,
        },
        signature::{
            AeadPrefs, FEATURE_SEIPDV2, FLAG_ENCRYPT_COMMUNICATIONS, FLAG_ENCRYPT_STORAGE,
            FLAG_SIGN, SIG_CERT_FIRST, SIG_CERT_LAST, SIG_DIRECT_KEY, SIG_KEY_REVOCATION,
            SIG_PRIMARY_BINDING, SIG_SUBKEY_BINDING, SIG_SUBKEY_REVOCATION, SigInfo, Signature,
            SymPrefs, hash_user_id,
        },
    },
    types::Fingerprint,
};

const SIG_CERT_REVOCATION: u8 = 0x30;
const ANONYMOUS_SENDER: &[u8; 20] = b"Anonymous Sender    ";
const MAX_KDF_PARAM_LEN: usize = 72;
const WEAK_RSA_BITS: usize = 3072;
const MAX_PACKETS: usize = 4096;

pub(crate) struct KdfParam {
    bytes: [u8; MAX_KDF_PARAM_LEN],
    len: u8,
}

impl KdfParam {
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.bytes.get(..usize::from(self.len)).unwrap_or_default()
    }
}

pub(crate) enum EncryptionKey {
    Rsa(RsaPublicKey),
    Ecdh {
        curve: EcdhCurve,
        point: Box<[u8]>,
        kdf_hash: HashAlgorithm,
        kek: AesKeySize,
        param: KdfParam,
    },
    X25519([u8; 32]),
    X448([u8; 56]),
    MlKem {
        ecdh: Box<[u8]>,
        kem: MlKemPublicKey,
    },
}

pub(crate) struct PgpKey {
    pub version: KeyVersion,
    pub algorithm: u8,
    pub fingerprint: Fingerprint,
    pub key_id: [u8; 8],
    pub seipd_v2: bool,
    pub sym_prefs: Option<SymPrefs>,
    pub aead_prefs: AeadPrefs,
    pub expires_at: Option<u64>,
    pub key: EncryptionKey,
}

impl PgpKey {
    pub(crate) fn is_post_quantum(&self) -> bool {
        matches!(self.key, EncryptionKey::MlKem { .. })
    }

    pub(crate) fn algorithm_name(&self) -> String {
        match &self.key {
            EncryptionKey::Rsa(key) => format!("RSA-{}", key.bits()),
            EncryptionKey::Ecdh {
                curve: EcdhCurve::Curve25519Legacy,
                ..
            } => "X25519".to_string(),
            EncryptionKey::Ecdh {
                curve: EcdhCurve::Nist(curve),
                ..
            } => format!("ECDH {}", curve.name()),
            EncryptionKey::X25519(_) => "X25519".to_string(),
            EncryptionKey::X448(_) => "X448".to_string(),
            EncryptionKey::MlKem { kem, .. } => match kem.kem() {
                MlKem::MlKem1024 => "ML-KEM-1024+X448".to_string(),
                kem => format!("{}+X25519", kem.name()),
            },
        }
    }

    pub(crate) fn heap_size(&self) -> usize {
        match &self.key {
            EncryptionKey::Rsa(key) => key.heap_size(),
            EncryptionKey::Ecdh { point, .. } => point.len(),
            EncryptionKey::X25519(_) | EncryptionKey::X448(_) => 0,
            EncryptionKey::MlKem { ecdh, kem } => ecdh.len() + kem.heap_size(),
        }
    }
}

impl PgpCert {
    pub(crate) fn heap_size(&self) -> usize {
        self.keys
            .iter()
            .map(|key| size_of::<PgpKey>() + key.heap_size())
            .sum()
    }
}

pub(crate) struct PgpCert {
    pub fingerprint: Fingerprint,
    pub keys: Box<[PgpKey]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Purpose {
    Encrypt,
    Verify,
}

pub(crate) const MAX_SIGNING_KEYS: usize = 4;
const MAX_ENCRYPTION_KEYS: usize = 16;

pub(crate) struct ValidCert {
    pub cert: PgpCert,
    pub addresses: Vec<Box<str>>,
    pub weak_rsa: bool,
    pub signing: [Option<Fingerprint>; MAX_SIGNING_KEYS],
}

struct RawSubkey<'x> {
    key: Result<KeyPacket<'x>, KeyError>,
    signatures: Vec<Signature<'x>>,
}

struct RawUser<'x> {
    user_id: &'x [u8],
    signatures: Vec<Signature<'x>>,
}

pub(crate) struct RawCert<'x> {
    primary: Result<KeyPacket<'x>, KeyError>,
    direct: Vec<Signature<'x>>,
    users: Vec<RawUser<'x>>,
    subkeys: Vec<RawSubkey<'x>>,
}

enum Slot {
    Primary,
    User,
    Subkey,
    Ignored,
}

pub(crate) fn split_certs(data: &[u8]) -> Result<Vec<RawCert<'_>>, KeyError> {
    let mut certs: Vec<RawCert<'_>> = Vec::new();
    let mut slot = Slot::Ignored;
    for (count, packet) in PacketReader::new(data).enumerate() {
        if count >= MAX_PACKETS {
            return Err(KeyError::TooLarge);
        }
        let Packet { tag, body } = packet?;
        match tag {
            TAG_PUBLIC_KEY => {
                certs.push(RawCert {
                    primary: KeyPacket::parse(body),
                    direct: Vec::new(),
                    users: Vec::new(),
                    subkeys: Vec::new(),
                });
                slot = Slot::Primary;
                continue;
            }
            TAG_SECRET_KEY | TAG_SECRET_SUBKEY => return Err(KeyError::SecretKey),
            TAG_MARKER | TAG_PADDING | TAG_TRUST => continue,
            _ => {}
        }
        let cert = certs.last_mut().ok_or(KeyError::MalformedPacket)?;
        match tag {
            TAG_SIGNATURE => {
                let Ok(signature) = Signature::parse(body) else {
                    continue;
                };
                match slot {
                    Slot::Primary => cert.direct.push(signature),
                    Slot::User => {
                        if let Some(user) = cert.users.last_mut() {
                            user.signatures.push(signature);
                        }
                    }
                    Slot::Subkey => {
                        if let Some(subkey) = cert.subkeys.last_mut() {
                            subkey.signatures.push(signature);
                        }
                    }
                    Slot::Ignored => {}
                }
            }
            TAG_USER_ID => {
                cert.users.push(RawUser {
                    user_id: body,
                    signatures: Vec::new(),
                });
                slot = Slot::User;
            }
            TAG_USER_ATTRIBUTE => slot = Slot::Ignored,
            TAG_PUBLIC_SUBKEY => {
                cert.subkeys.push(RawSubkey {
                    key: KeyPacket::parse(body),
                    signatures: Vec::new(),
                });
                slot = Slot::Subkey;
            }
            0..40 => return Err(KeyError::MalformedPacket),
            _ => slot = Slot::Ignored,
        }
    }
    if certs.is_empty() {
        Err(KeyError::Empty)
    } else {
        Ok(certs)
    }
}

fn newest_valid<'s, 'x>(
    signatures: impl Iterator<Item = &'s Signature<'x>>,
    mut verify: impl FnMut(&Signature<'x>) -> bool,
) -> Option<&'s Signature<'x>>
where
    'x: 's,
{
    let mut candidates: Vec<&Signature<'x>> = signatures.collect();
    candidates.sort_unstable_by_key(|sig| std::cmp::Reverse(sig.info.created.unwrap_or(0)));
    candidates.into_iter().find(|sig| verify(sig))
}

fn is_signing_algorithm(algorithm: u8) -> bool {
    matches!(
        algorithm,
        ALG_RSA
            | ALG_RSA_SIGN
            | ALG_ECDSA
            | ALG_EDDSA_LEGACY
            | ALG_ED25519
            | ALG_ED448
            | ALG_MLDSA65_ED25519
            | ALG_MLDSA87_ED448
    )
}

fn expiry(created: u32, info: &SigInfo) -> Option<u64> {
    info.key_expires
        .map(|exp| u64::from(created) + u64::from(exp))
}

pub(crate) fn email_address(user_id: &[u8]) -> Option<Box<str>> {
    let text = std::str::from_utf8(user_id).ok()?.trim();
    let address = match text.rsplit_once('<') {
        Some((_, rest)) => rest.split_once('>')?.0.trim(),
        None => text,
    };
    let (local, domain) = address.split_once('@')?;
    (!local.is_empty() && !domain.is_empty() && !address.contains(char::is_whitespace))
        .then(|| address.into())
}

impl<'x> RawCert<'x> {
    pub(crate) fn validate(
        &self,
        primaries: &[&KeyPacket<'x>],
        now: u64,
        purpose: Purpose,
    ) -> Result<ValidCert, KeyError> {
        let primary = self.primary.as_ref().map_err(|err| *err)?;
        if !is_signing_algorithm(primary.algorithm) {
            return Err(KeyError::UnsupportedPrimaryAlgorithm);
        }
        let verify_self =
            |sig: &Signature<'_>, data: &dyn Fn(&mut crate::backend::hash::Hasher)| {
                sig.is_issued_by(primary) && sig.verify(primary, data, now).is_ok()
            };
        let key_data = |h: &mut crate::backend::hash::Hasher| primary.hash_into(h);

        let revoked = self
            .direct
            .iter()
            .filter(|sig| sig.sig_type == SIG_KEY_REVOCATION)
            .any(|sig| {
                if sig.is_issued_by(primary) {
                    return sig.verify(primary, key_data, now).is_ok();
                }
                self.direct
                    .iter()
                    .filter_map(|d| d.info.revocation_key)
                    .filter(|fp| Some(*fp) == sig.info.issuer_fingerprint)
                    .filter_map(|fp| primaries.iter().find(|p| p.fingerprint == fp))
                    .any(|revoker| sig.verify(revoker, key_data, now).is_ok())
            });
        if revoked {
            return Err(KeyError::Revoked);
        }

        let direct = newest_valid(
            self.direct.iter().filter(|s| s.sig_type == SIG_DIRECT_KEY),
            |sig| verify_self(sig, &key_data),
        );
        let mut addresses = Vec::new();
        let mut primary_info: Option<SigInfo> = None;
        let mut primary_info_rank = (false, 0u32);
        for user in &self.users {
            let user_data = |h: &mut crate::backend::hash::Hasher| {
                primary.hash_into(h);
                hash_user_id(h, user.user_id);
            };
            let Some(sig) = newest_valid(
                user.signatures
                    .iter()
                    .filter(|s| (SIG_CERT_FIRST..=SIG_CERT_LAST).contains(&s.sig_type)),
                |sig| verify_self(sig, &user_data),
            ) else {
                continue;
            };
            let created = sig.info.created.unwrap_or(0);
            let revoked = user
                .signatures
                .iter()
                .filter(|s| {
                    s.sig_type == SIG_CERT_REVOCATION && s.info.created.unwrap_or(0) >= created
                })
                .any(|s| verify_self(s, &user_data));
            if revoked {
                continue;
            }
            if let Some(address) = email_address(user.user_id) {
                addresses.push(address);
            }
            let rank = (sig.info.primary_uid, created);
            if primary_info.is_none() || rank > primary_info_rank {
                primary_info = Some(sig.info);
                primary_info_rank = rank;
            }
        }
        let info = match (primary.version, direct, primary_info) {
            (KeyVersion::V6, Some(direct), _) => direct.info,
            (KeyVersion::V6, None, _) => return Err(KeyError::NoValidSelfSignature),
            (KeyVersion::V4, _, Some(info)) => info,
            (KeyVersion::V4, Some(direct), None) => direct.info,
            (KeyVersion::V4, None, None) => return Err(KeyError::NoValidSelfSignature),
        };
        let primary_expiry = expiry(primary.created, &info)
            .or_else(|| direct.and_then(|d| expiry(primary.created, &d.info)));
        if primary_expiry.is_some_and(|exp| exp <= now) {
            return Err(KeyError::Expired);
        }

        let mut error = KeyError::NoEncryptionKey;
        let mut candidates = vec![(primary, info, primary_expiry, None)];
        for subkey in &self.subkeys {
            let key = match &subkey.key {
                Ok(key) if key.version == primary.version => key,
                Ok(_) => continue,
                Err(err) => {
                    error = *err;
                    continue;
                }
            };
            let subkey_data = |h: &mut crate::backend::hash::Hasher| {
                primary.hash_into(h);
                key.hash_into(h);
            };
            let revoked = subkey
                .signatures
                .iter()
                .filter(|s| s.sig_type == SIG_SUBKEY_REVOCATION)
                .any(|s| verify_self(s, &subkey_data));
            if revoked {
                continue;
            }
            let Some(binding) = newest_valid(
                subkey
                    .signatures
                    .iter()
                    .filter(|s| s.sig_type == SIG_SUBKEY_BINDING),
                |sig| verify_self(sig, &subkey_data),
            ) else {
                continue;
            };
            let expires_at = match (expiry(key.created, &binding.info), primary_expiry) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
            candidates.push((key, binding.info, expires_at, Some(binding)));
        }

        let mut keys = Vec::new();
        let mut weak_rsa = false;
        let mut signing = [None; MAX_SIGNING_KEYS];
        let mut signing_slots = signing.iter_mut();
        for (key, binding, expires_at, binding_sig) in candidates {
            let flags = binding.key_flags.unwrap_or(0);
            let expired = expires_at.is_some_and(|exp| exp <= now);
            if purpose == Purpose::Verify
                && !expired
                && match binding_sig {
                    None => binding.key_flags.is_none_or(|f| f & FLAG_SIGN != 0),
                    Some(sig) => {
                        flags & FLAG_SIGN != 0 && has_primary_binding(sig, primary, key, now)
                    }
                }
                && let Some(slot) = signing_slots.next()
            {
                *slot = Some(key.fingerprint);
            }
            if flags & (FLAG_ENCRYPT_COMMUNICATIONS | FLAG_ENCRYPT_STORAGE) == 0
                || keys.len() >= MAX_ENCRYPTION_KEYS
            {
                continue;
            }
            if expired {
                error = KeyError::Expired;
                continue;
            }
            let features = binding.features.or(info.features);
            match encryption_key(key) {
                Ok((encryption_key, weak)) => {
                    weak_rsa |= weak;
                    keys.push(PgpKey {
                        version: key.version,
                        algorithm: key.algorithm,
                        fingerprint: key.fingerprint,
                        key_id: key.key_id(),
                        seipd_v2: features
                            .map(|f| f & FEATURE_SEIPDV2 != 0)
                            .unwrap_or(key.version == KeyVersion::V6),
                        sym_prefs: binding.sym_prefs.or(info.sym_prefs),
                        aead_prefs: binding.aead_prefs.or(info.aead_prefs).unwrap_or_default(),
                        expires_at,
                        key: encryption_key,
                    });
                }
                Err(err) => error = err,
            }
        }
        if keys.is_empty() && (purpose == Purpose::Encrypt || signing[0].is_none()) {
            return Err(error);
        }
        Ok(ValidCert {
            cert: PgpCert {
                fingerprint: primary.fingerprint,
                keys: keys.into_boxed_slice(),
            },
            addresses,
            weak_rsa,
            signing,
        })
    }

    pub(crate) fn key(&self, fingerprint: &Fingerprint) -> Option<&KeyPacket<'x>> {
        self.primary
            .as_ref()
            .ok()
            .into_iter()
            .chain(self.subkeys.iter().filter_map(|s| s.key.as_ref().ok()))
            .find(|key| key.fingerprint == *fingerprint)
    }

    pub(crate) fn primary(&self) -> Option<&KeyPacket<'x>> {
        self.primary.as_ref().ok()
    }

    pub(crate) fn certified_by(&self, signers: &[&KeyPacket<'_>], address: &str, now: u64) -> bool {
        let Ok(primary) = &self.primary else {
            return false;
        };
        self.users.iter().any(|user| {
            email_address(user.user_id).is_some_and(|bound| bound.eq_ignore_ascii_case(address))
                && user
                    .signatures
                    .iter()
                    .filter(|sig| (SIG_CERT_FIRST..=SIG_CERT_LAST).contains(&sig.sig_type))
                    .any(|sig| {
                        signers.iter().any(|signer| {
                            signer.fingerprint != primary.fingerprint
                                && sig.is_issued_by(signer)
                                && sig
                                    .verify(
                                        signer,
                                        |h| {
                                            primary.hash_into(h);
                                            hash_user_id(h, user.user_id);
                                        },
                                        now,
                                    )
                                    .is_ok()
                        })
                    })
        })
    }
}

fn has_primary_binding(
    binding: &Signature<'_>,
    primary: &KeyPacket<'_>,
    subkey: &KeyPacket<'_>,
    now: u64,
) -> bool {
    binding
        .embedded
        .and_then(|body| Signature::parse(body).ok())
        .is_some_and(|back| {
            back.sig_type == SIG_PRIMARY_BINDING
                && back
                    .verify(
                        subkey,
                        |h| {
                            primary.hash_into(h);
                            subkey.hash_into(h);
                        },
                        now,
                    )
                    .is_ok()
        })
}

fn kdf_param(
    curve: EcdhCurve,
    hash_id: u8,
    kek_id: u8,
    fingerprint: &Fingerprint,
) -> Result<KdfParam, KeyError> {
    let mut param = KdfParam {
        bytes: [0u8; MAX_KDF_PARAM_LEN],
        len: 0,
    };
    let oid = curve.oid();
    let parts: [&[u8]; 5] = [
        &[oid.len() as u8],
        oid,
        &[ALG_ECDH, 3, 1, hash_id, kek_id],
        ANONYMOUS_SENDER,
        fingerprint.as_bytes(),
    ];
    let mut len = 0;
    for part in parts {
        let end = len + part.len();
        param
            .bytes
            .get_mut(len..end)
            .ok_or(KeyError::UnsupportedKeyAlgorithm)?
            .copy_from_slice(part);
        len = end;
    }
    param.len = len as u8;
    Ok(param)
}

fn encryption_key(key: &KeyPacket<'_>) -> Result<(EncryptionKey, bool), KeyError> {
    Ok(match key.material {
        KeyMaterial::Rsa { n, e } if key.algorithm != ALG_RSA_SIGN => {
            let rsa = RsaPublicKey::from_components(n, e).map_err(|_| KeyError::WeakRsa)?;
            let bits = rsa.bits();
            if !(MIN_RSA_BITS..=MAX_RSA_BITS).contains(&bits) {
                return Err(KeyError::WeakRsa);
            }
            (EncryptionKey::Rsa(rsa), bits < WEAK_RSA_BITS)
        }
        KeyMaterial::Ecdh {
            curve,
            point,
            kdf_hash,
            kek,
            kdf_hash_id,
            kek_id,
        } => {
            curve
                .curve()
                .validate_public(point)
                .map_err(|_| KeyError::InvalidPublicKey)?;
            (
                EncryptionKey::Ecdh {
                    curve,
                    point: point.into(),
                    kdf_hash,
                    kek,
                    param: kdf_param(curve, kdf_hash_id, kek_id, &key.fingerprint)?,
                },
                false,
            )
        }
        KeyMaterial::X25519(point) => (EncryptionKey::X25519(*point), false),
        KeyMaterial::X448(point) => (EncryptionKey::X448(*point), false),
        KeyMaterial::MlKem { kem, ecdh, mlkem } => {
            let curve = match kem {
                MlKem::MlKem1024 => Curve::X448,
                _ => Curve::X25519,
            };
            curve
                .validate_public(ecdh)
                .map_err(|_| KeyError::InvalidPublicKey)?;
            (
                EncryptionKey::MlKem {
                    ecdh: ecdh.into(),
                    kem: MlKemPublicKey::new(kem, mlkem).map_err(|_| KeyError::InvalidPublicKey)?,
                },
                false,
            )
        }
        _ => return Err(KeyError::UnsupportedKeyAlgorithm),
    })
}
