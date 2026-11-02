/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use zeroize::Zeroizing;

use crate::{
    backend::{
        aes::{AesCipher, BLOCK_LEN},
        agree::Curve,
        base64::MIME,
        hash::HashAlgorithm,
        kdf::{HkdfHash, x963},
        kem::{MlKem, MlKemPublicKey},
        rng::Rng,
        rsa::{OaepHash, RsaPublicKey},
        symmetric::{
            GCM_NONCE_LEN, GCM_TAG_LEN, GcmKey, cbc_encrypt_padded_in_place, cbc_pkcs7_padded_len,
            write_pkcs7_padding,
        },
    },
    der::{
        oid, tag,
        writer::{
            StackBuf, bit_string_len, small_integer_len, tlv_len, write_bit_string_header,
            write_header, write_small_integer, write_tlv,
        },
    },
    error::{EncryptError, ProfileError},
    mime::{Sink, entity::Entity},
    types::{EcdhWrapParameters, EncryptOptions, EncryptWarning, Profile},
    x509::recipient::{SmimeKey, SmimeRecipient},
};

const CEK_LEN: usize = 32;
const UKM_LEN: usize = 64;
const WRAPPED_LEN: usize = CEK_LEN + 8;
const NULL: &[u8] = &[tag::NULL, 0];
const NSS_SIZE_LIMIT: usize = 256 << 20;
const MAX_SHARED_INFO: usize = 128;
const MAX_KEM_INFO: usize = 32;

const SMIME_HEADERS_ENVELOPED: &[u8] = b"Content-Type: application/pkcs7-mime; smime-type=enveloped-data;\r\n\tname=\"smime.p7m\"\r\nContent-Disposition: attachment; filename=\"smime.p7m\"\r\nContent-Transfer-Encoding: base64\r\n\r\n";
const SMIME_HEADERS_AUTH: &[u8] = b"Content-Type: application/pkcs7-mime; smime-type=authEnveloped-data;\r\n\tname=\"smime.p7m\"\r\nContent-Disposition: attachment; filename=\"smime.p7m\"\r\nContent-Transfer-Encoding: base64\r\n\r\n";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Content {
    Cbc,
    Gcm,
}

fn alg_id_len(oid: &[u8], params_len: usize) -> usize {
    tlv_len(tlv_len(oid.len()) + params_len)
}

fn write_alg_id<S: Sink + ?Sized>(out: &mut S, oid: &[u8], params: &[u8]) {
    write_header(out, tag::SEQUENCE, tlv_len(oid.len()) + params.len());
    write_tlv(out, tag::OID, oid);
    out.put(params);
}

fn hash_oid(hash: OaepHash) -> &'static [u8] {
    match hash {
        OaepHash::Sha1 => oid::SHA1,
        OaepHash::Sha256 => oid::SHA256,
        OaepHash::Sha384 => oid::SHA384,
        OaepHash::Sha512 => oid::SHA512,
    }
}

fn oaep_params_len(hash: OaepHash) -> usize {
    if hash == OaepHash::Sha1 {
        return tlv_len(0);
    }
    let hash_alg = alg_id_len(hash_oid(hash), 0);
    tlv_len(tlv_len(hash_alg) + tlv_len(alg_id_len(oid::MGF1, hash_alg)))
}

fn write_oaep_params<S: Sink + ?Sized>(out: &mut S, hash: OaepHash) {
    if hash == OaepHash::Sha1 {
        write_header(out, tag::SEQUENCE, 0);
        return;
    }
    let hash_oid = hash_oid(hash);
    let hash_alg = alg_id_len(hash_oid, 0);
    let mgf = alg_id_len(oid::MGF1, hash_alg);
    write_header(out, tag::SEQUENCE, tlv_len(hash_alg) + tlv_len(mgf));
    write_header(out, tag::context_constructed(0), hash_alg);
    write_alg_id(out, hash_oid, &[]);
    write_header(out, tag::context_constructed(1), mgf);
    write_header(out, tag::SEQUENCE, tlv_len(oid::MGF1.len()) + hash_alg);
    write_tlv(out, tag::OID, oid::MGF1);
    write_alg_id(out, hash_oid, &[]);
}

fn rsa_padding(key: &SmimeKey, profile: Profile) -> Option<OaepHash> {
    match key {
        SmimeKey::Rsa {
            oaep: Some(hash), ..
        } => Some(*hash),
        SmimeKey::Rsa { oaep: None, .. } if profile != Profile::Compatible => {
            Some(OaepHash::Sha256)
        }
        _ => None,
    }
}

#[derive(Clone, Copy)]
enum KariKdf {
    X963(HashAlgorithm),
    Hkdf,
}

#[derive(Clone, Copy)]
enum Ukm {
    Absent,
    Random,
}

impl Ukm {
    fn explicit_len(self) -> usize {
        match self {
            Ukm::Absent => 0,
            Ukm::Random => tlv_len(tlv_len(UKM_LEN)),
        }
    }
}

#[derive(Clone, Copy)]
struct Kari<'r> {
    curve: Curve,
    point: &'r [u8],
    originator_oid: &'static [u8],
    scheme: &'static [u8],
    kdf: KariKdf,
    ukm: Ukm,
    wrap: &'static [u8],
}

#[derive(Clone, Copy)]
enum RecipientKind<'r> {
    Ktri {
        key: &'r RsaPublicKey,
        padding: Option<OaepHash>,
    },
    Kari(Kari<'r>),
    Kemri(&'r MlKemPublicKey),
}

fn wrap_params(wrap: EcdhWrapParameters) -> &'static [u8] {
    match wrap {
        EcdhWrapParameters::Absent => &[],
        EcdhWrapParameters::Null => NULL,
    }
}

fn mlkem_wrap(kem: MlKem) -> (&'static [u8], usize) {
    match kem {
        MlKem::MlKem512 => (oid::AES128_WRAP, 16),
        _ => (oid::AES256_WRAP, 32),
    }
}

fn mlkem_oid(kem: MlKem) -> &'static [u8] {
    match kem {
        MlKem::MlKem512 => oid::ML_KEM_512,
        MlKem::MlKem768 => oid::ML_KEM_768,
        MlKem::MlKem1024 => oid::ML_KEM_1024,
    }
}

impl<'r> RecipientKind<'r> {
    fn new(key: &'r SmimeKey, options: &EncryptOptions) -> Self {
        let hkdf = |curve, point, originator_oid| {
            RecipientKind::Kari(Kari {
                curve,
                point,
                originator_oid,
                scheme: oid::ECDH_HKDF_SHA256,
                kdf: KariKdf::Hkdf,
                ukm: Ukm::Random,
                wrap: &[],
            })
        };
        match key {
            SmimeKey::Rsa { key: rsa, .. } => RecipientKind::Ktri {
                key: rsa,
                padding: rsa_padding(key, options.profile),
            },
            SmimeKey::Ec { curve, point } => {
                let (scheme, hash) = match curve {
                    Curve::P256 => (oid::ECDH_SHA256_KDF, HashAlgorithm::Sha256),
                    Curve::P384 => (oid::ECDH_SHA384_KDF, HashAlgorithm::Sha384),
                    _ => (oid::ECDH_SHA512_KDF, HashAlgorithm::Sha512),
                };
                RecipientKind::Kari(Kari {
                    curve: *curve,
                    point,
                    originator_oid: oid::EC_PUBLIC_KEY,
                    scheme,
                    kdf: KariKdf::X963(hash),
                    ukm: match options.ecdh_wrap_parameters {
                        EcdhWrapParameters::Absent => Ukm::Absent,
                        EcdhWrapParameters::Null => Ukm::Random,
                    },
                    wrap: wrap_params(options.ecdh_wrap_parameters),
                })
            }
            SmimeKey::X25519(point) => hkdf(Curve::X25519, point.as_slice(), oid::X25519),
            SmimeKey::X448(point) => hkdf(Curve::X448, point.as_slice(), oid::X448),
            SmimeKey::MlKem(kem) => RecipientKind::Kemri(kem),
        }
    }

    fn ktri_alg_len(padding: Option<OaepHash>) -> usize {
        match padding {
            Some(hash) => alg_id_len(oid::RSAES_OAEP, oaep_params_len(hash)),
            None => alg_id_len(oid::RSA_ENCRYPTION, NULL.len()),
        }
    }

    fn kemri_body_len(kem: MlKem, rid: usize) -> usize {
        let (wrap_oid, kek_len) = mlkem_wrap(kem);
        small_integer_len(0)
            + rid
            + alg_id_len(mlkem_oid(kem), 0)
            + tlv_len(kem.ciphertext_len())
            + alg_id_len(oid::HKDF_SHA256, 0)
            + small_integer_len(kek_len as u32)
            + alg_id_len(wrap_oid, 0)
            + tlv_len(WRAPPED_LEN)
    }

    fn content_len(&self, rid: usize) -> usize {
        match self {
            RecipientKind::Ktri { key, padding } => {
                small_integer_len(0)
                    + rid
                    + Self::ktri_alg_len(*padding)
                    + tlv_len(key.ciphertext_len())
            }
            RecipientKind::Kemri(kem) => {
                tlv_len(oid::ORI_KEM.len()) + tlv_len(Self::kemri_body_len(kem.kem(), rid))
            }
            RecipientKind::Kari(kari) => {
                small_integer_len(3)
                    + tlv_len(kari.originator_len())
                    + kari.ukm.explicit_len()
                    + alg_id_len(kari.scheme, alg_id_len(oid::AES256_WRAP, kari.wrap.len()))
                    + tlv_len(tlv_len(rid + tlv_len(WRAPPED_LEN)))
            }
        }
    }

    fn len(&self, rid: usize) -> usize {
        tlv_len(self.content_len(rid))
    }
}

impl Kari<'_> {
    fn originator_len(&self) -> usize {
        tlv_len(alg_id_len(self.originator_oid, 0) + bit_string_len(self.curve.public_len()))
    }
}

fn write_explicit_ukm<S: Sink + ?Sized>(out: &mut S, number: u8, ukm: Option<&[u8]>) {
    if let Some(ukm) = ukm {
        write_header(out, tag::context_constructed(number), tlv_len(ukm.len()));
        write_tlv(out, tag::OCTET_STRING, ukm);
    }
}

fn write_ri(
    out: &mut Vec<u8>,
    kind: &RecipientKind<'_>,
    rid: &[u8],
    cek: &[u8],
    rng: &mut impl Rng,
) -> Result<(), EncryptError> {
    match kind {
        RecipientKind::Ktri { key, padding } => {
            write_header(out, tag::SEQUENCE, kind.content_len(rid.len()));
            write_small_integer(out, 0);
            out.extend_from_slice(rid);
            match padding {
                Some(hash) => {
                    write_header(
                        out,
                        tag::SEQUENCE,
                        tlv_len(oid::RSAES_OAEP.len()) + oaep_params_len(*hash),
                    );
                    write_tlv(out, tag::OID, oid::RSAES_OAEP);
                    write_oaep_params(out, *hash);
                }
                None => write_alg_id(out, oid::RSA_ENCRYPTION, NULL),
            }
            write_header(out, tag::OCTET_STRING, key.ciphertext_len());
            let start = out.len();
            out.resize(start + key.ciphertext_len(), 0);
            let slot = out.get_mut(start..).unwrap_or_default();
            match padding {
                Some(hash) => key.encrypt_oaep(*hash, cek, slot)?,
                None => key.encrypt_pkcs1(cek, slot)?,
            }
        }
        RecipientKind::Kemri(kem) => {
            let (wrap_oid, kek_len) = mlkem_wrap(kem.kem());
            let encapsulation = kem.encapsulate()?;
            let mut info = StackBuf::<MAX_KEM_INFO>::new();
            write_header(
                &mut info,
                tag::SEQUENCE,
                alg_id_len(wrap_oid, 0) + small_integer_len(kek_len as u32),
            );
            write_alg_id(&mut info, wrap_oid, &[]);
            write_small_integer(&mut info, kek_len as u32);
            let mut kek = Zeroizing::new([0u8; 32]);
            let kek = kek.get_mut(..kek_len).unwrap_or_default();
            HkdfHash::Sha256.derive(
                &[],
                &[encapsulation.shared()],
                &[info.as_slice().ok_or(EncryptError::MalformedMessage)?],
                kek,
            )?;
            write_header(
                out,
                tag::context_constructed(4),
                kind.content_len(rid.len()),
            );
            write_tlv(out, tag::OID, oid::ORI_KEM);
            write_header(
                out,
                tag::SEQUENCE,
                RecipientKind::kemri_body_len(kem.kem(), rid.len()),
            );
            write_small_integer(out, 0);
            out.extend_from_slice(rid);
            write_alg_id(out, mlkem_oid(kem.kem()), &[]);
            write_tlv(out, tag::OCTET_STRING, encapsulation.ciphertext());
            write_alg_id(out, oid::HKDF_SHA256, &[]);
            write_small_integer(out, kek_len as u32);
            write_alg_id(out, wrap_oid, &[]);
            write_header(out, tag::OCTET_STRING, WRAPPED_LEN);
            let start = out.len();
            out.resize(start + WRAPPED_LEN, 0);
            AesCipher::new(kek)?.wrap(cek, out.get_mut(start..).unwrap_or_default())?;
        }
        RecipientKind::Kari(kari) => {
            let agreement = kari.curve.ephemeral_agree(kari.point, rng)?;
            let mut ukm_bytes = [0u8; UKM_LEN];
            let ukm = match kari.ukm {
                Ukm::Absent => None,
                Ukm::Random => {
                    rng.fill(&mut ukm_bytes)?;
                    Some(ukm_bytes.as_slice())
                }
            };

            let wrap_alg = alg_id_len(oid::AES256_WRAP, kari.wrap.len());
            let mut shared_info = StackBuf::<MAX_SHARED_INFO>::new();
            write_header(
                &mut shared_info,
                tag::SEQUENCE,
                wrap_alg + kari.ukm.explicit_len() + tlv_len(tlv_len(4)),
            );
            write_alg_id(&mut shared_info, oid::AES256_WRAP, kari.wrap);
            write_explicit_ukm(&mut shared_info, 0, ukm);
            write_header(&mut shared_info, tag::context_constructed(2), tlv_len(4));
            write_tlv(
                &mut shared_info,
                tag::OCTET_STRING,
                &((CEK_LEN * 8) as u32).to_be_bytes(),
            );
            let shared_info = shared_info
                .as_slice()
                .ok_or(EncryptError::MalformedMessage)?;
            let mut kek = Zeroizing::new([0u8; CEK_LEN]);
            match kari.kdf {
                KariKdf::X963(hash) => x963(hash, agreement.shared(), shared_info, kek.as_mut())?,
                KariKdf::Hkdf => HkdfHash::Sha256.derive(
                    ukm.unwrap_or_default(),
                    &[agreement.shared()],
                    &[shared_info],
                    kek.as_mut(),
                )?,
            }

            write_header(
                out,
                tag::context_constructed(1),
                kind.content_len(rid.len()),
            );
            write_small_integer(out, 3);
            write_header(out, tag::context_constructed(0), kari.originator_len());
            write_header(
                out,
                tag::context_constructed(1),
                alg_id_len(kari.originator_oid, 0) + bit_string_len(kari.curve.public_len()),
            );
            write_alg_id(out, kari.originator_oid, &[]);
            write_bit_string_header(out, kari.curve.public_len());
            out.extend_from_slice(agreement.public());
            write_explicit_ukm(out, 1, ukm);
            write_header(out, tag::SEQUENCE, tlv_len(kari.scheme.len()) + wrap_alg);
            write_tlv(out, tag::OID, kari.scheme);
            write_alg_id(out, oid::AES256_WRAP, kari.wrap);
            write_header(
                out,
                tag::SEQUENCE,
                tlv_len(rid.len() + tlv_len(WRAPPED_LEN)),
            );
            write_header(out, tag::SEQUENCE, rid.len() + tlv_len(WRAPPED_LEN));
            out.extend_from_slice(rid);
            write_header(out, tag::OCTET_STRING, WRAPPED_LEN);
            let start = out.len();
            out.resize(start + WRAPPED_LEN, 0);
            AesCipher::new(kek.as_ref())?.wrap(cek, out.get_mut(start..).unwrap_or_default())?;
        }
    }
    Ok(())
}

pub(crate) fn check_profile(
    recipients: &[SmimeRecipient],
    profile: Profile,
) -> Result<(), ProfileError> {
    if profile == Profile::PostQuantum
        && recipients
            .iter()
            .any(|r| !matches!(r.key, SmimeKey::MlKem(_)))
    {
        return Err(ProfileError::NoPostQuantumKey);
    }
    Ok(())
}

pub(crate) fn encrypt(
    message: &Entity<'_>,
    recipients: &[SmimeRecipient],
    options: &EncryptOptions,
    rng: &mut impl Rng,
) -> Result<(Vec<u8>, Option<EncryptWarning>), EncryptError> {
    if recipients.is_empty() {
        return Err(EncryptError::NoRecipients);
    }
    check_profile(recipients, options.profile)?;
    let content = if options.profile == Profile::Compatible {
        Content::Cbc
    } else {
        Content::Gcm
    };
    let inner_len = message.inner_len();
    let content_len = match content {
        Content::Cbc => cbc_pkcs7_padded_len(inner_len),
        Content::Gcm => inner_len,
    };
    let ris: usize = recipients
        .iter()
        .map(|r| RecipientKind::new(&r.key, options).len(r.issuer_and_serial.len()))
        .sum();
    let version = if content == Content::Gcm {
        0
    } else if recipients
        .iter()
        .any(|r| matches!(r.key, SmimeKey::MlKem(_)))
    {
        3
    } else if recipients
        .iter()
        .any(|r| !matches!(r.key, SmimeKey::Rsa { .. }))
    {
        2
    } else {
        0
    };
    let (content_oid, params_len, type_oid, smime_headers) = match content {
        Content::Cbc => (
            oid::AES256_CBC,
            tlv_len(BLOCK_LEN),
            oid::ENVELOPED_DATA,
            SMIME_HEADERS_ENVELOPED,
        ),
        Content::Gcm => (
            oid::AES256_GCM,
            tlv_len(tlv_len(GCM_NONCE_LEN) + small_integer_len(GCM_TAG_LEN as u32)),
            oid::AUTH_ENVELOPED_DATA,
            SMIME_HEADERS_AUTH,
        ),
    };
    let eci = tlv_len(oid::DATA.len()) + alg_id_len(content_oid, params_len) + tlv_len(content_len);
    let body = small_integer_len(version)
        + tlv_len(ris)
        + tlv_len(eci)
        + match content {
            Content::Cbc => 0,
            Content::Gcm => tlv_len(GCM_TAG_LEN),
        };
    let content_info = tlv_len(type_oid.len()) + tlv_len(tlv_len(body));
    let total = tlv_len(content_info);

    let mut cek = Zeroizing::new([0u8; CEK_LEN]);
    rng.fill(cek.as_mut())?;
    let mut iv = [0u8; BLOCK_LEN];
    let iv = match content {
        Content::Cbc => &mut iv[..],
        Content::Gcm => &mut iv[..GCM_NONCE_LEN],
    };
    rng.fill(iv)?;

    let mut scratch = Vec::with_capacity(total);
    write_header(&mut scratch, tag::SEQUENCE, content_info);
    write_tlv(&mut scratch, tag::OID, type_oid);
    write_header(&mut scratch, tag::context_constructed(0), tlv_len(body));
    write_header(&mut scratch, tag::SEQUENCE, body);
    write_small_integer(&mut scratch, version);
    write_header(&mut scratch, tag::SET, ris);
    for recipient in recipients {
        let start = scratch.len();
        let kind = RecipientKind::new(&recipient.key, options);
        let rid = &recipient.issuer_and_serial;
        write_ri(&mut scratch, &kind, rid, cek.as_ref(), rng)?;
        if scratch.len() - start != kind.len(rid.len()) {
            return Err(EncryptError::MalformedMessage);
        }
    }
    write_header(&mut scratch, tag::SEQUENCE, eci);
    write_tlv(&mut scratch, tag::OID, oid::DATA);
    write_header(
        &mut scratch,
        tag::SEQUENCE,
        tlv_len(content_oid.len()) + params_len,
    );
    write_tlv(&mut scratch, tag::OID, content_oid);
    match content {
        Content::Cbc => write_tlv(&mut scratch, tag::OCTET_STRING, iv),
        Content::Gcm => {
            write_header(
                &mut scratch,
                tag::SEQUENCE,
                tlv_len(GCM_NONCE_LEN) + small_integer_len(GCM_TAG_LEN as u32),
            );
            write_tlv(&mut scratch, tag::OCTET_STRING, iv);
            write_small_integer(&mut scratch, GCM_TAG_LEN as u32);
        }
    }
    write_header(&mut scratch, tag::context(0), content_len);
    let start = scratch.len();
    message.write_inner(&mut scratch);
    match content {
        Content::Cbc => {
            write_pkcs7_padding(&mut scratch, inner_len);
            let mut cbc_iv = [0u8; BLOCK_LEN];
            cbc_iv.copy_from_slice(iv);
            cbc_encrypt_padded_in_place(cek.as_ref(), cbc_iv, &mut scratch[start..])?;
        }
        Content::Gcm => {
            let mut nonce = [0u8; GCM_NONCE_LEN];
            nonce.copy_from_slice(iv);
            let mac =
                GcmKey::new(cek.as_ref())?.seal_in_place(nonce, &[], &mut scratch[start..])?;
            write_tlv(&mut scratch, tag::OCTET_STRING, &mac);
        }
    }
    if scratch.len() != total {
        return Err(EncryptError::MalformedMessage);
    }

    let mut out = Vec::with_capacity(
        message.outer_len() + smime_headers.len() + MIME.encoded_len(scratch.len()),
    );
    message.write_outer(&mut out);
    out.extend_from_slice(smime_headers);
    MIME.encode_append(&scratch, &mut out);
    let warning = (scratch.len() > NSS_SIZE_LIMIT).then_some(EncryptWarning::ExceedsNssLimit);
    Ok((out, warning))
}
